import { Queue, QueueOptions } from "bullmq";
import IORedis from "ioredis";
import { envConfig } from "../../config/env.config";
import {
  CRON_QUEUE_NAME,
  CronJobName,
  DEFAULT_CRON_SCHEDULES,
} from "../constants/cron.constant";

export interface CronJobData {
  jobName: CronJobName;
  triggeredAt: string;
  params?: Record<string, unknown>;
}

export interface CronScheduleOverride {
  cron: string;
  isEnabled?: boolean;
  params?: Record<string, unknown>;
}

export type CronSchedulesInput =
  | string[]
  | Partial<Record<CronJobName, CronScheduleOverride>>;

export interface CronQueueServiceOptions {
  queue?: Queue<CronJobData>;
  redisConnection?: IORedis;
  connectTimeoutMs?: number;
  disableAutoInit?: boolean;
}

const DEFAULT_REDIS_CONNECT_TIMEOUT_MS = 5000;

const isTestEnv =
  process.env.NODE_ENV === "test" ||
  process.argv.some((arg) => arg.includes("test")) ||
  process.env.npm_lifecycle_event === "test";

export class CronQueueService {
  private queue?: Queue<CronJobData>;
  private redisConnection?: IORedis;
  private isRedisAvailable = false;
  private connectPromise?: Promise<boolean>;
  private pendingSchedules?: Partial<Record<CronJobName, CronScheduleOverride>>;
  private desiredRevision = 0;
  private syncedRevision = 0;
  private activeSyncPromise?: Promise<void>;
  private readonly connectTimeoutMs: number;

  constructor(options?: CronQueueServiceOptions) {
    this.connectTimeoutMs =
      options?.connectTimeoutMs ?? DEFAULT_REDIS_CONNECT_TIMEOUT_MS;

    if (options) {
      if (options.queue) {
        this.queue = options.queue;
      }
      if (options.redisConnection) {
        this.attachRedisConnection(options.redisConnection);
        if (!this.queue) {
          this.queue = new Queue<CronJobData>(CRON_QUEUE_NAME, {
            connection: options.redisConnection,
            defaultJobOptions: {
              attempts: 2,
              backoff: {
                type: "exponential",
                delay: 5000,
              },
              removeOnComplete: true,
              removeOnFail: false,
            },
          });
        }
      }
      if (
        !options.disableAutoInit &&
        !options.redisConnection &&
        !options.queue &&
        !isTestEnv &&
        envConfig.redis.enabled
      ) {
        this.init();
      }
      return;
    }

    if (!isTestEnv && envConfig.redis.enabled) {
      this.init();
    }
  }

  private attachRedisConnection(conn: IORedis): void {
    this.redisConnection = conn;

    const handleReady = () => {
      this.isRedisAvailable = true;
      if (this.pendingSchedules && this.syncedRevision < this.desiredRevision) {
        void this.flushPendingSchedules();
      }
    };

    const handleUnavailable = () => {
      this.isRedisAvailable = false;
      this.syncedRevision = 0;
    };

    conn.on("connect", handleReady);
    conn.on("ready", handleReady);
    conn.on("error", handleUnavailable);
    conn.on("close", handleUnavailable);

    if (conn.status === "ready" || conn.status === "connect") {
      this.isRedisAvailable = true;
      this.connectPromise = Promise.resolve(true);
    } else if (typeof conn.connect === "function") {
      this.connectPromise = conn
        .connect()
        .then(() => {
          this.isRedisAvailable = true;
          return true;
        })
        .catch(() => {
          this.isRedisAvailable = false;
          return false;
        });
    }
  }

  private init(): void {
    try {
      const connection = new IORedis({
        host: envConfig.redis.host,
        port: envConfig.redis.port,
        password: envConfig.redis.password,
        maxRetriesPerRequest: null,
        enableReadyCheck: false,
        lazyConnect: true,
        retryStrategy: (times) => {
          if (times > 2) {
            this.isRedisAvailable = false;
            return null;
          }
          return Math.min(times * 200, 500);
        },
      });

      this.attachRedisConnection(connection);

      const queueOptions: QueueOptions = {
        connection,
        defaultJobOptions: {
          attempts: 2,
          backoff: {
            type: "exponential",
            delay: 5000,
          },
          removeOnComplete: true,
          removeOnFail: false,
        },
      };

      this.queue = new Queue<CronJobData>(CRON_QUEUE_NAME, queueOptions);
    } catch {
      this.isRedisAvailable = false;
    }
  }

  private async waitUntilRedisReady(): Promise<boolean> {
    if (this.isRedisAvailable) return true;
    if (!this.connectPromise) return false;

    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const timeoutPromise = new Promise<boolean>((resolve) => {
        timer = setTimeout(
          () => resolve(this.isRedisAvailable),
          this.connectTimeoutMs,
        );
      });
      await Promise.race([this.connectPromise, timeoutPromise]);
      return this.isRedisAvailable;
    } finally {
      if (timer) {
        clearTimeout(timer);
      }
    }
  }

  private normalizeSchedulesInput(
    configOrDisabled: CronSchedulesInput,
  ): Partial<Record<CronJobName, CronScheduleOverride>> {
    const isDisabledArray = Array.isArray(configOrDisabled);
    const disabledSet = new Set(isDisabledArray ? configOrDisabled : []);
    const customMap = isDisabledArray ? {} : configOrDisabled;
    const normalized: Partial<Record<CronJobName, CronScheduleOverride>> = {};

    for (const [rawJobName, defaultConfig] of Object.entries(
      DEFAULT_CRON_SCHEDULES,
    )) {
      const jobName = rawJobName as CronJobName;
      const override = customMap[jobName];
      const isDisabled = isDisabledArray
        ? disabledSet.has(jobName)
        : override?.isEnabled === false;
      normalized[jobName] = {
        cron: override?.cron || defaultConfig.cron,
        isEnabled: !isDisabled,
        params:
          override?.params && Object.keys(override.params).length > 0
            ? { ...override.params }
            : undefined,
      };
    }

    return normalized;
  }

  private async applySchedulesSnapshot(
    scheduleMap: Partial<Record<CronJobName, CronScheduleOverride>>,
  ): Promise<void> {
    if (!this.queue || !this.isRedisAvailable) return;

    try {
      for (const [rawJobName, defaultConfig] of Object.entries(
        DEFAULT_CRON_SCHEDULES,
      )) {
        const jobName = rawJobName as CronJobName;
        const override = scheduleMap[jobName];
        const isDisabled = override?.isEnabled === false;

        if (isDisabled) {
          await this.queue.removeJobScheduler(jobName).catch(() => {});
          continue;
        }

        const pattern = override?.cron || defaultConfig.cron;
        const params =
          override?.params && Object.keys(override.params).length > 0
            ? override.params
            : undefined;

        await this.queue.upsertJobScheduler(
          jobName,
          { pattern, tz: "Asia/Ho_Chi_Minh" },
          {
            name: jobName,
            data: {
              jobName,
              triggeredAt: new Date().toISOString(),
              ...(params ? { params } : {}),
            },
          },
        );
      }
      console.log("[CronQueue] Repeatable cron jobs successfully registered");
    } catch (err: any) {
      console.warn(
        "[CronQueue] Failed to register repeatable schedules:",
        err.message,
      );
    }
  }

  private flushPendingSchedules(): Promise<void> {
    if (this.activeSyncPromise) {
      return this.activeSyncPromise;
    }

    let syncRun!: Promise<void>;
    syncRun = (async () => {
      try {
        while (
          this.queue &&
          this.isRedisAvailable &&
          this.pendingSchedules &&
          this.syncedRevision < this.desiredRevision
        ) {
          const targetRevision = this.desiredRevision;
          const snapshot: Partial<Record<CronJobName, CronScheduleOverride>> = {
            ...this.pendingSchedules,
          };
          await this.applySchedulesSnapshot(snapshot);
          this.syncedRevision = targetRevision;
        }
      } finally {
        if (this.activeSyncPromise === syncRun) {
          this.activeSyncPromise = undefined;
        }
      }
    })();

    this.activeSyncPromise = syncRun;
    return syncRun;
  }

  /**
   * Đăng ký tất cả các Repeatable Cron Jobs theo biểu thức cron chuẩn hoặc cấu hình động từ DB.
   * Chờ Redis kết nối xong và tự động đồng bộ lại nếu Redis sẵn sàng muộn hơn lúc khởi động.
   * @param configOrDisabled Danh sách job bị tắt (legacy) hoặc bản đồ cấu hình từng job
   */
  async registerSchedules(
    configOrDisabled: CronSchedulesInput = [],
  ): Promise<void> {
    this.pendingSchedules = this.normalizeSchedulesInput(configOrDisabled);
    this.desiredRevision += 1;

    const ready = await this.waitUntilRedisReady();
    if (!this.queue || !ready) {
      return;
    }

    await this.flushPendingSchedules();
  }

  /**
   * Bật hoặc cập nhật lịch trình cho một cron job cụ thể (upsert vào BullMQ scheduler)
   */
  async enableJobScheduler(
    jobName: CronJobName,
    options?: { cron?: string; params?: Record<string, unknown> },
  ): Promise<void> {
    const defaultConfig = DEFAULT_CRON_SCHEDULES[jobName];
    if (!defaultConfig) return;
    const pattern = options?.cron || defaultConfig.cron;
    const params =
      options?.params && Object.keys(options.params).length > 0
        ? options.params
        : undefined;

    if (!this.pendingSchedules) {
      this.pendingSchedules = {};
    }
    this.pendingSchedules[jobName] = {
      cron: pattern,
      isEnabled: true,
      params,
    };

    const ready = await this.waitUntilRedisReady();
    if (!this.queue || !ready) {
      this.desiredRevision += 1;
      return;
    }

    try {
      await this.queue.upsertJobScheduler(
        jobName,
        { pattern, tz: "Asia/Ho_Chi_Minh" },
        {
          name: jobName,
          data: {
            jobName,
            triggeredAt: new Date().toISOString(),
            ...(params ? { params } : {}),
          },
        },
      );
    } catch (err: any) {
      console.warn(
        `[CronQueue] Failed to enable scheduler for ${jobName}:`,
        err.message,
      );
    }
  }

  /**
   * Tắt lịch trình cho một cron job cụ thể (xóa khỏi BullMQ scheduler)
   */
  async disableJobScheduler(jobName: CronJobName): Promise<void> {
    if (!this.pendingSchedules) {
      this.pendingSchedules = {};
    }
    const existingCron =
      this.pendingSchedules[jobName]?.cron ||
      DEFAULT_CRON_SCHEDULES[jobName]?.cron ||
      "0 0 * * *";
    this.pendingSchedules[jobName] = {
      ...this.pendingSchedules[jobName],
      cron: existingCron,
      isEnabled: false,
    };

    const ready = await this.waitUntilRedisReady();
    if (!this.queue || !ready) {
      this.desiredRevision += 1;
      return;
    }

    try {
      await this.queue.removeJobScheduler(jobName).catch(() => {});
    } catch (err: any) {
      console.warn(
        `[CronQueue] Failed to disable scheduler for ${jobName}:`,
        err.message,
      );
    }
  }

  /**
   * Đưa 1 job vào hàng đợi thực thi ngay lập tức
   */
  async triggerJob(
    jobName: CronJobName,
    params?: Record<string, unknown>,
  ): Promise<{ jobId: string }> {
    const data: CronJobData = {
      jobName,
      triggeredAt: new Date().toISOString(),
      params,
    };

    if (this.queue && this.isRedisAvailable) {
      const job = await this.queue.add(`manual:${jobName}`, data);
      return { jobId: job.id || `manual-${Date.now()}` };
    }

    return { jobId: `direct-${Date.now()}` };
  }

  getQueueInstance(): Queue<CronJobData> | undefined {
    return this.queue;
  }

  async close(): Promise<void> {
    if (this.queue) {
      await this.queue.close().catch(() => {});
      this.queue = undefined;
    }
    if (this.redisConnection) {
      this.redisConnection.disconnect();
      this.redisConnection = undefined;
    }
    this.isRedisAvailable = false;
    this.connectPromise = undefined;
    this.pendingSchedules = undefined;
    this.desiredRevision = 0;
    this.syncedRevision = 0;
    this.activeSyncPromise = undefined;
  }
}

export const cronQueue = new CronQueueService();
