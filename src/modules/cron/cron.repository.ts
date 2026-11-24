import { Prisma } from "@prisma/client";
import { prisma } from "../../database/prisma.client";
import {
  CRON_CONFIG_CATEGORY,
  CRON_CONFIG_KEY_PREFIX,
  CRON_JOB_NAMES,
  CronJobName,
} from "../../common/constants/cron.constant";
import {
  ActivitySummaryStatsDto,
  StoredCronJobConfig,
} from "./cron.dto";
import {
  userRepository,
  UserRepository,
} from "../users/user.repository";

export class CronRepository {
  private readonly userRepo: UserRepository;

  constructor(userRepo?: UserRepository) {
    this.userRepo = userRepo || userRepository;
  }

  /**
   * Xóa toàn bộ các bản ghi Audit Logs tạo trước thời điểm cutoffDate
   */
  async deleteAuditLogsOlderThan(cutoffDate: Date): Promise<number> {
    // SEC-18: Guard chống xóa các bản ghi trong vòng 30 ngày gần nhất
    const minSafeCutoff = new Date(
      Date.now() - 30 * 24 * 60 * 60 * 1000 + 60000,
    );
    if (!cutoffDate || cutoffDate > minSafeCutoff) {
      throw new Error(
        "cutoffDate không được nằm trong phạm vi 30 ngày gần nhất để tránh xóa nhầm dữ liệu kiểm toán",
      );
    }
    const result = await prisma.auditLog.deleteMany({
      where: {
        createdAt: { lt: cutoffDate },
      },
    });
    return result.count;
  }

  /**
   * Xóa toàn bộ các token xác thực và phiên đã hết hạn
   */
  async deleteExpiredTokens(cutoffDate: Date): Promise<{
    refreshTokensCount: number;
    verificationTokensCount: number;
    passwordResetTokensCount: number;
  }> {
    const [refreshRes, verifyRes, resetRes] = await prisma.$transaction([
      prisma.refreshToken.deleteMany({
        where: { expiresAt: { lt: cutoffDate } },
      }),
      prisma.verificationToken.deleteMany({
        where: { expiresAt: { lt: cutoffDate } },
      }),
      prisma.passwordResetToken.deleteMany({
        where: { expiresAt: { lt: cutoffDate } },
      }),
    ]);

    return {
      refreshTokensCount: refreshRes.count,
      verificationTokensCount: verifyRes.count,
      passwordResetTokensCount: resetRes.count,
    };
  }

  /**
   * Lấy toàn bộ danh sách avatarUrl hiện tại của các User đang lưu trong DB
   */
  async getAllUserAvatarUrls(): Promise<string[]> {
    return this.userRepo.getAllUserAvatarUrls();
  }

  /**
   * Tổng hợp thống kê hoạt động hệ thống trong khoảng thời gian từ startDate đến endDate
   */
  async getActivityStats(
    startDate: Date,
    endDate: Date,
  ): Promise<ActivitySummaryStatsDto> {
    const [
      newUsersCount,
      activeSessionsCount,
      webhookDeliveriesCount,
      auditLogsCount,
    ] = await prisma.$transaction([
      prisma.user.count({
        where: {
          createdAt: { gte: startDate, lte: endDate },
        },
      }),
      prisma.refreshToken.count({
        where: {
          createdAt: { gte: startDate, lte: endDate },
        },
      }),
      prisma.webhookDelivery.count({
        where: {
          createdAt: { gte: startDate, lte: endDate },
        },
      }),
      prisma.auditLog.count({
        where: {
          createdAt: { gte: startDate, lte: endDate },
        },
      }),
    ]);

    return {
      newUsersCount,
      activeSessionsCount,
      notificationsSentCount: 0,
      emailsSentCount: 0,
      webhookDeliveriesCount,
      auditLogsCount,
    };
  }

  /**
   * Lấy danh sách email của tất cả người dùng có quyền Quản trị (vai trò ADMIN / SUPER_ADMIN)
   */
  async findAdminUsers(): Promise<
    Array<{ id: string; email: string; fullName: string | null }>
  > {
    return this.userRepo.findAdminUsers();
  }

  /**
   * Đọc cấu hình cron job bền vững đã lưu trong system_configs (nếu có)
   */
  async findJobConfig(jobName: CronJobName): Promise<StoredCronJobConfig | null> {
    try {
      const record = await prisma.systemConfig.findUnique({
        where: { key: `${CRON_CONFIG_KEY_PREFIX}${jobName}` },
      });
      if (!record || !record.value || typeof record.value !== "object") {
        return null;
      }
      return record.value as unknown as StoredCronJobConfig;
    } catch {
      return null;
    }
  }

  /**
   * Đọc toàn bộ cấu hình cron jobs đã lưu trong system_configs
   */
  async findAllJobConfigs(): Promise<
    Partial<Record<CronJobName, StoredCronJobConfig>>
  > {
    try {
      const validNames = new Set<string>(Object.values(CRON_JOB_NAMES));
      const rows = await prisma.systemConfig.findMany({
        where: {
          key: { startsWith: CRON_CONFIG_KEY_PREFIX },
        },
      });
      const result: Partial<Record<CronJobName, StoredCronJobConfig>> = {};
      for (const row of rows) {
        const jobName = row.key.slice(CRON_CONFIG_KEY_PREFIX.length);
        if (
          validNames.has(jobName) &&
          row.value &&
          typeof row.value === "object" &&
          !Array.isArray(row.value)
        ) {
          result[jobName as CronJobName] =
            row.value as unknown as StoredCronJobConfig;
        }
      }
      return result;
    } catch {
      return {};
    }
  }

  /**
   * Lưu bền vững cấu hình cron job vào bảng system_configs
   */
  async upsertJobConfig(
    jobName: CronJobName,
    config: StoredCronJobConfig,
  ): Promise<void> {
    const key = `${CRON_CONFIG_KEY_PREFIX}${jobName}`;
    await prisma.systemConfig.upsert({
      where: { key },
      update: {
        value: config as unknown as Prisma.InputJsonObject,
        description: config.description,
        category: CRON_CONFIG_CATEGORY,
        isPublic: false,
      },
      create: {
        key,
        value: config as unknown as Prisma.InputJsonObject,
        description: config.description,
        category: CRON_CONFIG_CATEGORY,
        isPublic: false,
      },
    });
  }

  /**
   * Tạo bản ghi Audit Log ghi vết thao tác Cron Job
   */
  async createAuditLog(data: {
    actorId?: string;
    action: string;
    targetType: string;
    targetId: string;
    details?: Record<string, unknown>;
    ipAddress?: string;
    userAgent?: string;
  }): Promise<void> {
    await prisma.auditLog.create({
      data: {
        actorId: data.actorId,
        action: data.action,
        targetType: data.targetType,
        targetId: data.targetId,
        details: (data.details as Prisma.InputJsonObject) || Prisma.JsonNull,
        ipAddress: data.ipAddress,
        userAgent: data.userAgent,
      },
    });
  }
}

export const cronRepository = new CronRepository();
