import { Prisma } from "@prisma/client";
import { prisma } from "../../database/prisma.client";
import { ActivitySummaryStatsDto } from "./cron.dto";
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
