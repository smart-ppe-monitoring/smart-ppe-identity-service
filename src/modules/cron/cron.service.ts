import { CronRepository, cronRepository } from "./cron.repository";
import { AppError } from "../../common/errors/app-error";
import { ERROR_CODE } from "../../common/errors/error-code";
import { R2Service } from "../../common/services/r2.service";
import { notificationDispatcher } from "../../common/services/notification-dispatcher.service";
import {
  CRON_JOB_NAMES,
  CronJobName,
  CronScheduleConfig,
  DEFAULT_CRON_PARAMS,
  DEFAULT_CRON_SCHEDULES,
  DEFAULT_AUDIT_LOG_RETENTION_DAYS,
  DEFAULT_UNCONFIRMED_UPLOAD_MAX_AGE_HOURS,
  buildCronFromSchedule,
  formatCronScheduleLabel,
  parseScheduleFromCron,
} from "../../common/constants/cron.constant";
import {
  AUDIT_ACTION,
  AUDIT_TARGET_TYPE,
} from "../../common/constants/audit-log.constant";
import {
  EMAIL_TEMPLATE_KEY,
  NOTIFICATION_CHANNEL,
} from "../../common/constants/notification.constant";
import {
  formatVietnamDate,
  getVietnamDayRange,
} from "../../common/helpers/date.helper";
import {
  CronJobDefaultParamsDto,
  CronJobExecutionResultDto,
  CronJobItemDto,
  StoredCronJobConfig,
  ToggleCronJobResultDto,
  UpdateCronJobDto,
} from "./cron.dto";
import { CronQueueService, cronQueue } from "../../common/queues/cron.queue";
import { outboxRepository } from "../../common/repositories/outbox.repository";

export class CronService {
  /**
   * Cache cấu hình lịch chạy, mô tả, trạng thái bật/tắt và tham số mặc định của từng cron job.
   * Khởi tạo từ DEFAULT_CRON_SCHEDULES và đồng bộ bền vững với bảng system_configs.
   */
  private readonly jobConfigs: Map<CronJobName, StoredCronJobConfig> = new Map(
    (Object.keys(DEFAULT_CRON_SCHEDULES) as CronJobName[]).map((name) => [
      name,
      {
        cron: DEFAULT_CRON_SCHEDULES[name].cron,
        description: DEFAULT_CRON_SCHEDULES[name].description,
        isEnabled: true,
        defaultParams: { ...DEFAULT_CRON_PARAMS[name] },
      },
    ]),
  );
  private configsLoaded = false;

  constructor(
    private readonly repository: CronRepository = cronRepository,
    private readonly r2Service: R2Service = new R2Service(),
    private readonly cronQueueService: CronQueueService = cronQueue,
  ) {}

  private sanitizeDefaultParams(
    jobName: CronJobName,
    rawParams?: CronJobDefaultParamsDto | Record<string, unknown>,
    fallback: CronJobDefaultParamsDto = DEFAULT_CRON_PARAMS[jobName] || {},
  ): CronJobDefaultParamsDto {
    if (jobName === CRON_JOB_NAMES.CLEANUP_AUDIT_LOGS) {
      const rawDays = rawParams?.retentionDays;
      if (rawDays !== undefined) {
        if (
          typeof rawDays !== "number" ||
          !Number.isInteger(rawDays) ||
          rawDays < 30 ||
          rawDays > 3650
        ) {
          throw new AppError(
            "Thời gian lưu trữ Audit Log mặc định phải là số nguyên từ 30 đến 3650 ngày",
            400,
            ERROR_CODE.VALIDATION_ERROR,
          );
        }
        return { retentionDays: rawDays };
      }
      return {
        retentionDays:
          fallback.retentionDays ?? DEFAULT_AUDIT_LOG_RETENTION_DAYS,
      };
    }

    if (jobName === CRON_JOB_NAMES.CLEANUP_UNCONFIRMED_UPLOADS) {
      const rawHours = rawParams?.maxAgeHours;
      if (rawHours !== undefined) {
        if (
          typeof rawHours !== "number" ||
          !Number.isInteger(rawHours) ||
          rawHours < 1 ||
          rawHours > 720
        ) {
          throw new AppError(
            "Thời gian tối đa dọn dẹp upload phải là số nguyên từ 1 đến 720 giờ",
            400,
            ERROR_CODE.VALIDATION_ERROR,
          );
        }
        return { maxAgeHours: rawHours };
      }
      return {
        maxAgeHours:
          fallback.maxAgeHours ?? DEFAULT_UNCONFIRMED_UPLOAD_MAX_AGE_HOURS,
      };
    }

    return {};
  }

  private async ensureConfigsLoaded(): Promise<void> {
    if (this.configsLoaded) return;
    this.configsLoaded = true;

    if (typeof (this.repository as any).findAllJobConfigs !== "function") {
      return;
    }

    const storedMap = await (this.repository as any).findAllJobConfigs();
    if (!storedMap || typeof storedMap !== "object") {
      return;
    }

    for (const jobName of Object.keys(DEFAULT_CRON_SCHEDULES) as CronJobName[]) {
      const stored = storedMap[jobName];
      if (!stored || typeof stored !== "object") continue;

      const current = this.jobConfigs.get(jobName)!;
      const mergedParams =
        stored.defaultParams && typeof stored.defaultParams === "object"
          ? { ...current.defaultParams, ...stored.defaultParams }
          : current.defaultParams;

      this.jobConfigs.set(jobName, {
        cron:
          typeof stored.cron === "string" && stored.cron.trim()
            ? stored.cron.trim()
            : current.cron,
        description:
          typeof stored.description === "string" && stored.description.trim()
            ? stored.description.trim()
            : current.description,
        isEnabled:
          typeof stored.isEnabled === "boolean"
            ? stored.isEnabled
            : current.isEnabled,
        defaultParams: mergedParams,
      });
    }
  }

  private toJobItemDto(
    jobName: CronJobName,
    config: StoredCronJobConfig,
  ): CronJobItemDto {
    const schedule: CronScheduleConfig = parseScheduleFromCron(config.cron);
    return {
      name: jobName,
      cron: config.cron,
      schedule,
      scheduleLabel: formatCronScheduleLabel(schedule),
      description: config.description,
      isEnabled: config.isEnabled,
      defaultParams: { ...config.defaultParams },
      lastStatus: "READY",
    };
  }

  /**
   * Nạp toàn bộ cấu hình cron job từ CSDL và đồng bộ vào BullMQ khi server khởi động
   */
  async syncSchedulers(): Promise<void> {
    await this.ensureConfigsLoaded();
    const scheduleMap: Partial<
      Record<
        CronJobName,
        { cron: string; isEnabled: boolean; params: Record<string, unknown> }
      >
    > = {};

    for (const [jobName, cfg] of this.jobConfigs.entries()) {
      scheduleMap[jobName] = {
        cron: cfg.cron,
        isEnabled: cfg.isEnabled,
        params: { ...cfg.defaultParams },
      };
    }

    await this.cronQueueService.registerSchedules(scheduleMap);
  }

  /**
   * Danh sách toàn bộ các tác vụ định kỳ đã đăng ký trong hệ thống
   */
  async listJobs(search?: string): Promise<CronJobItemDto[]> {
    await this.ensureConfigsLoaded();

    const jobs: CronJobItemDto[] = (
      Object.keys(DEFAULT_CRON_SCHEDULES) as CronJobName[]
    ).map((name) => this.toJobItemDto(name, this.jobConfigs.get(name)!));

    if (search) {
      const lower = search.toLowerCase();
      return jobs.filter(
        (j) =>
          j.name.toLowerCase().includes(lower) ||
          j.description.toLowerCase().includes(lower) ||
          j.scheduleLabel.toLowerCase().includes(lower),
      );
    }

    return jobs;
  }

  /**
   * Cập nhật lịch chạy trực quan, mô tả, trạng thái hoặc tham số mặc định của Cron Job
   */
  async updateJob(
    jobName: CronJobName,
    dto: UpdateCronJobDto,
    actorContext?: { actorId?: string; ipAddress?: string; userAgent?: string },
  ): Promise<CronJobItemDto> {
    if (!DEFAULT_CRON_SCHEDULES[jobName]) {
      throw new AppError(
        `Job name '${jobName}' không được hỗ trợ`,
        400,
        ERROR_CODE.VALIDATION_ERROR,
      );
    }

    await this.ensureConfigsLoaded();
    const prev = this.jobConfigs.get(jobName)!;

    const nextCron = dto.schedule
      ? buildCronFromSchedule(dto.schedule)
      : prev.cron;
    const nextDescription =
      dto.description !== undefined && dto.description.trim().length > 0
        ? dto.description.trim()
        : prev.description;
    const nextIsEnabled =
      dto.isEnabled !== undefined ? dto.isEnabled : prev.isEnabled;
    const nextDefaultParams =
      dto.defaultParams !== undefined
        ? this.sanitizeDefaultParams(jobName, dto.defaultParams, prev.defaultParams)
        : { ...prev.defaultParams };

    const nextConfig: StoredCronJobConfig = {
      cron: nextCron,
      description: nextDescription,
      isEnabled: nextIsEnabled,
      defaultParams: nextDefaultParams,
    };

    if (typeof (this.repository as any).upsertJobConfig === "function") {
      await (this.repository as any).upsertJobConfig(jobName, nextConfig);
    }
    this.jobConfigs.set(jobName, nextConfig);

    if (nextConfig.isEnabled) {
      await this.cronQueueService.enableJobScheduler(jobName, {
        cron: nextConfig.cron,
        params: { ...nextConfig.defaultParams },
      });
    } else {
      await this.cronQueueService.disableJobScheduler(jobName);
    }

    await this.repository.createAuditLog({
      actorId: actorContext?.actorId,
      action: AUDIT_ACTION.UPDATE_CRON_JOB,
      targetType: AUDIT_TARGET_TYPE.CRON_JOB,
      targetId: jobName,
      details: {
        previous: prev,
        updated: nextConfig,
        scheduleInput: dto.schedule ?? null,
      },
      ipAddress: actorContext?.ipAddress,
      userAgent: actorContext?.userAgent,
    });

    return this.toJobItemDto(jobName, nextConfig);
  }

  /**
   * Toggle trạng thái enable/disable của một cron job.
   * Lưu bền vững và đồng bộ với BullMQ scheduler.
   */
  async toggleJob(
    jobName: CronJobName,
    actorContext?: { actorId?: string; ipAddress?: string; userAgent?: string },
  ): Promise<ToggleCronJobResultDto> {
    await this.ensureConfigsLoaded();
    const current = this.jobConfigs.get(jobName) || {
      cron: DEFAULT_CRON_SCHEDULES[jobName].cron,
      description: DEFAULT_CRON_SCHEDULES[jobName].description,
      isEnabled: true,
      defaultParams: { ...DEFAULT_CRON_PARAMS[jobName] },
    };
    const newState = !current.isEnabled;
    const nextConfig: StoredCronJobConfig = {
      ...current,
      isEnabled: newState,
    };

    if (typeof (this.repository as any).upsertJobConfig === "function") {
      await (this.repository as any).upsertJobConfig(jobName, nextConfig);
    }
    this.jobConfigs.set(jobName, nextConfig);

    if (newState) {
      await this.cronQueueService.enableJobScheduler(jobName, {
        cron: nextConfig.cron,
        params: { ...nextConfig.defaultParams },
      });
    } else {
      await this.cronQueueService.disableJobScheduler(jobName);
    }

    await this.repository.createAuditLog({
      actorId: actorContext?.actorId,
      action: AUDIT_ACTION.TOGGLE_CRON_JOB,
      targetType: AUDIT_TARGET_TYPE.CRON_JOB,
      targetId: jobName,
      details: { isEnabled: newState },
      ipAddress: actorContext?.ipAddress,
      userAgent: actorContext?.userAgent,
    });

    return { jobName, isEnabled: newState };
  }

  /**
   * 1. Dọn dẹp các bản ghi Audit Logs cũ hơn số ngày quy định (mặc định 30 ngày)
   */
  async executeAuditLogCleanup(
    retentionDays = DEFAULT_AUDIT_LOG_RETENTION_DAYS,
  ): Promise<{
    deletedCount: number;
    retentionDays: number;
    cutoffDate: string;
  }> {
    // SEC-18: Kiểm tra cận dưới tối thiểu 30 ngày (Defense-in-depth)
    if (!Number.isFinite(retentionDays) || retentionDays < 30) {
      throw new AppError(
        "Thời gian lưu trữ Audit Log tối thiểu phải từ 30 ngày để đảm bảo an toàn bằng chứng kiểm toán",
        400,
        ERROR_CODE.VALIDATION_ERROR,
      );
    }

    const cutoffDate = new Date(
      Date.now() - retentionDays * 24 * 60 * 60 * 1000,
    );
    const deletedCount =
      await this.repository.deleteAuditLogsOlderThan(cutoffDate);

    // Ghi audit log hệ thống về việc dọn dẹp
    await this.repository.createAuditLog({
      action: AUDIT_ACTION.CLEANUP_AUDIT_LOGS,
      targetType: AUDIT_TARGET_TYPE.CRON_JOB,
      targetId: CRON_JOB_NAMES.CLEANUP_AUDIT_LOGS,
      details: {
        deletedCount,
        retentionDays,
        cutoffDate: cutoffDate.toISOString(),
      },
    });

    return {
      deletedCount,
      retentionDays,
      cutoffDate: cutoffDate.toISOString(),
    };
  }

  /**
   * 2. Quét và dọn dẹp các file tải lên không xác nhận / rác trên Cloudflare R2 / S3
   */
  async executeUploadsCleanup(
    maxAgeHours = DEFAULT_UNCONFIRMED_UPLOAD_MAX_AGE_HOURS,
  ): Promise<{
    scannedCount: number;
    deletedCount: number;
    deletedKeys: string[];
  }> {
    const now = Date.now();
    const maxAgeMs = maxAgeHours * 60 * 60 * 1000;

    // Lấy toàn bộ danh sách file trong thư mục avatars/
    const objects = await this.r2Service.listObjects("avatars/");
    if (objects.length === 0) {
      return { scannedCount: 0, deletedCount: 0, deletedKeys: [] };
    }

    // Lấy toàn bộ các avatarUrl đang được User trong cơ sở dữ liệu liên kết
    const activeUrls = await this.repository.getAllUserAvatarUrls();
    const activeKeySet = new Set<string>();

    for (const url of activeUrls) {
      // url có dạng https://.../avatars/user-id/xyz.webp -> lấy 'avatars/user-id/xyz.webp'
      const match = url.match(/avatars\/.+$/);
      if (match) {
        activeKeySet.add(match[0]);
      }
    }

    const deletedKeys: string[] = [];

    for (const obj of objects) {
      // Nếu file chưa từng được liên kết với bất kỳ User nào và đã tồn tại quá maxAgeHours
      const isOrphaned = !activeKeySet.has(obj.key);
      const isOldEnough = obj.lastModified
        ? now - obj.lastModified.getTime() > maxAgeMs
        : false;

      if (isOrphaned && isOldEnough) {
        deletedKeys.push(obj.key);
      }
    }

    if (deletedKeys.length > 0) {
      if (typeof this.r2Service.deleteFiles === "function") {
        await this.r2Service.deleteFiles(deletedKeys).catch((err: any) => {
          console.warn(
            `[CronService] Failed to batch delete orphaned files:`,
            err.message,
          );
        });
      } else {
        for (const key of deletedKeys) {
          await this.r2Service.deleteFile(key).catch(() => {});
        }
      }
    }

    if (deletedKeys.length > 0) {
      await this.repository.createAuditLog({
        action: AUDIT_ACTION.CLEANUP_UNCONFIRMED_UPLOADS,
        targetType: AUDIT_TARGET_TYPE.CRON_JOB,
        targetId: CRON_JOB_NAMES.CLEANUP_UNCONFIRMED_UPLOADS,
        details: {
          scannedCount: objects.length,
          deletedCount: deletedKeys.length,
          maxAgeHours,
        },
      });
    }

    return {
      scannedCount: objects.length,
      deletedCount: deletedKeys.length,
      deletedKeys,
    };
  }

  /**
   * 3. Dọn dẹp định kỳ các Token xác thực và phiên đã hết hạn
   */
  async executeExpiredTokensCleanup(): Promise<{
    refreshTokensCount: number;
    verificationTokensCount: number;
    passwordResetTokensCount: number;
    totalDeleted: number;
  }> {
    const now = new Date();
    const result = await this.repository.deleteExpiredTokens(now);

    // Dọn dẹp các Outbox Events đã hoàn tất (PUBLISHED) cũ hơn 24 giờ
    const outboxCutoff = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const outboxDeleted = await outboxRepository
      .deletePublishedOlderThan(outboxCutoff)
      .catch(() => 0);

    const totalDeleted =
      result.refreshTokensCount +
      result.verificationTokensCount +
      result.passwordResetTokensCount +
      outboxDeleted;

    if (totalDeleted > 0) {
      await this.repository.createAuditLog({
        action: AUDIT_ACTION.CLEANUP_EXPIRED_TOKENS,
        targetType: AUDIT_TARGET_TYPE.CRON_JOB,
        targetId: CRON_JOB_NAMES.CLEANUP_EXPIRED_TOKENS,
        details: { ...result, outboxDeleted, totalDeleted },
      });
    }

    return {
      ...result,
      totalDeleted,
    };
  }

  /**
   * 4. Tổng hợp hoạt động định kỳ (Hàng ngày / Hàng tuần) và gửi email báo cáo tới Quản trị viên
   */
  async executeSummaryDigest(options: { period: "DAILY" | "WEEKLY" }): Promise<{
    period: "DAILY" | "WEEKLY";
    startDate: string;
    endDate: string;
    stats: any;
    recipientCount: number;
  }> {
    const durationDays = options.period === "WEEKLY" ? 7 : 1;
    const prevDate = new Date(Date.now() - durationDays * 24 * 60 * 60 * 1000);
    const startDateStr = formatVietnamDate(prevDate);
    const endDateStr = formatVietnamDate(
      new Date(Date.now() - 24 * 60 * 60 * 1000),
    );

    const { startOfDay: startDate } = getVietnamDayRange(startDateStr);
    const { endOfDay: endDate } = getVietnamDayRange(endDateStr);

    const stats = await this.repository.getActivityStats(startDate, endDate);
    const admins = await this.repository.findAdminUsers();

    const periodText = options.period === "WEEKLY" ? "Hàng tuần" : "Hàng ngày";

    for (const admin of admins) {
      if (admin.email) {
        await notificationDispatcher
          .send({
            userId: admin.id,
            channels: [NOTIFICATION_CHANNEL.EMAIL],
            email: {
              toEmail: admin.email,
              templateKey: EMAIL_TEMPLATE_KEY.ACTIVITY_SUMMARY_DIGEST,
              templateData: {
                period: periodText,
                startDate: startDateStr,
                endDate: endDateStr,
                ...stats,
              },
            },
          })
          .catch((err: any) => {
            console.warn(
              `[CronService] Failed to send digest email to ${admin.email}:`,
              err.message,
            );
          });
      }
    }

    await this.repository.createAuditLog({
      action: AUDIT_ACTION.SEND_SUMMARY_DIGEST,
      targetType: AUDIT_TARGET_TYPE.CRON_JOB,
      targetId:
        options.period === "WEEKLY"
          ? CRON_JOB_NAMES.WEEKLY_SUMMARY_DIGEST
          : CRON_JOB_NAMES.DAILY_SUMMARY_DIGEST,
      details: { period: options.period, stats, recipientCount: admins.length },
    });

    return {
      period: options.period,
      startDate: startDate.toISOString(),
      endDate: endDate.toISOString(),
      stats,
      recipientCount: admins.length,
    };
  }

  /**
   * Kích hoạt chạy ngay một Cron Job bất kỳ (Manual trigger từ Admin)
   */
  async triggerJob(
    jobName: CronJobName,
    params: Record<string, unknown> = {},
    actorContext?: { actorId?: string; ipAddress?: string; userAgent?: string },
  ): Promise<CronJobExecutionResultDto> {
    await this.ensureConfigsLoaded();
    const configuredDefaults =
      this.jobConfigs.get(jobName)?.defaultParams || {};
    const effectiveParams: Record<string, unknown> = {
      ...configuredDefaults,
      ...params,
    };

    const startTime = Date.now();

    let executionData: Record<string, unknown> | undefined;

    switch (jobName) {
      case CRON_JOB_NAMES.CLEANUP_AUDIT_LOGS: {
        const days =
          typeof effectiveParams["retentionDays"] === "number"
            ? effectiveParams["retentionDays"]
            : DEFAULT_AUDIT_LOG_RETENTION_DAYS;
        executionData = await this.executeAuditLogCleanup(days);
        break;
      }
      case CRON_JOB_NAMES.CLEANUP_UNCONFIRMED_UPLOADS: {
        const hours =
          typeof effectiveParams["maxAgeHours"] === "number"
            ? effectiveParams["maxAgeHours"]
            : DEFAULT_UNCONFIRMED_UPLOAD_MAX_AGE_HOURS;
        executionData = await this.executeUploadsCleanup(hours);
        break;
      }
      case CRON_JOB_NAMES.CLEANUP_EXPIRED_TOKENS: {
        executionData = await this.executeExpiredTokensCleanup();
        break;
      }
      case CRON_JOB_NAMES.DAILY_SUMMARY_DIGEST: {
        executionData = await this.executeSummaryDigest({ period: "DAILY" });
        break;
      }
      case CRON_JOB_NAMES.WEEKLY_SUMMARY_DIGEST: {
        executionData = await this.executeSummaryDigest({ period: "WEEKLY" });
        break;
      }
      default:
        throw new AppError(
          `Job name '${jobName}' không được hỗ trợ`,
          400,
          ERROR_CODE.VALIDATION_ERROR,
        );
    }

    const durationMs = Date.now() - startTime;

    // Ghi Audit Log hành động trigger của Admin
    await this.repository.createAuditLog({
      actorId: actorContext?.actorId,
      action: AUDIT_ACTION.TRIGGER_CRON_JOB,
      targetType: AUDIT_TARGET_TYPE.CRON_JOB,
      targetId: jobName,
      details: { params, durationMs, result: executionData },
      ipAddress: actorContext?.ipAddress,
      userAgent: actorContext?.userAgent,
    });

    return {
      jobName,
      success: true,
      durationMs,
      data: executionData,
    };
  }
}

export const cronService = new CronService();
