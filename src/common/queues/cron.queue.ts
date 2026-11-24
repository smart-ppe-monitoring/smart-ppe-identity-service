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

const isTestEnv =
  process.env.NODE_ENV === "test" ||
  process.argv.some((arg) => arg.includes("test")) ||
  process.env.npm_lifecycle_event === "test";

export class CronQueueService {
  private queue?: Queue<CronJobData>;
  private redisConnection?: IORedis;
  private isRedisAvailable = false;

  constructor() {
    if (!isTestEnv && envConfig.redis.enabled) {
      this.init();
    }
  }

  private init(): void {
    try {
      this.redisConnection = new IORedis({
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

      this.redisConnection.on("connect", () => {
        this.isRedisAvailable = true;
      });

      this.redisConnection.on("error", () => {
        this.isRedisAvailable = false;
      });

      this.redisConnection.connect().catch(() => {
        this.isRedisAvailable = false;
      });

      const queueOptions: QueueOptions = {
        connection: this.redisConnection,
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

  /**
   * Đăng ký tất cả các Repeatable Cron Jobs theo biểu thức cron chuẩn hoặc cấu hình động từ DB.
   * @param configOrDisabled Danh sách job bị tắt (legacy) hoặc bản đồ cấu hình từng job
   */
  async registerSchedules(
    configOrDisabled:
      | string[]
      | Partial<
          Record<
            CronJobName,
            {
              cron: string;
              isEnabled?: boolean;
              params?: Record<string, unknown>;
            }
          >
        > = [],
  ): Promise<void> {
    if (!this.queue || !this.isRedisAvailable) return;

    const isDisabledArray = Array.isArray(configOrDisabled);
    const disabledSet = new Set(isDisabledArray ? configOrDisabled : []);
    const customMap = isDisabledArray ? {} : configOrDisabled;

    try {
      for (const [rawJobName, defaultConfig] of Object.entries(
        DEFAULT_CRON_SCHEDULES,
      )) {
        const jobName = rawJobName as CronJobName;
        const override = customMap[jobName];
        const isDisabled = isDisabledArray
          ? disabledSet.has(jobName)
          : override?.isEnabled === false;

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

  /**
   * Bật hoặc cập nhật lịch trình cho một cron job cụ thể (upsert vào BullMQ scheduler)
   */
  async enableJobScheduler(
    jobName: CronJobName,
    options?: { cron?: string; params?: Record<string, unknown> },
  ): Promise<void> {
    if (!this.queue || !this.isRedisAvailable) return;
    const defaultConfig = DEFAULT_CRON_SCHEDULES[jobName];
    if (!defaultConfig) return;
    const pattern = options?.cron || defaultConfig.cron;
    const params =
      options?.params && Object.keys(options.params).length > 0
        ? options.params
        : undefined;
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
    if (!this.queue || !this.isRedisAvailable) return;
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
  }
}

export const cronQueue = new CronQueueService();
