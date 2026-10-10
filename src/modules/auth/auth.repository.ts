import { Prisma } from "@prisma/client";
import {
  prisma,
  DEFAULT_TRANSACTION_OPTIONS,
} from "../../database/prisma.client";
import { ROLES } from "../../common/constants/role.constant";
import { PERMISSIONS } from "../../common/constants/permission.constant";
import {
  VERIFICATION_TOKEN_TYPE,
  VerificationTokenType,
} from "../../common/constants/verification-token.constant";
import { hashToken } from "../../common/helpers/crypto.helper";

export class AuthRepository {
  findByEmail(email: string) {
    return prisma.user.findFirst({
      where: { email, deletedAt: null },
      include: { role: true },
    });
  }

  findById(id: string) {
    return prisma.user.findFirst({
      where: { id, deletedAt: null },
      include: { role: true },
    });
  }

  findProfileById(id: string) {
    return prisma.user.findFirst({
      where: { id, deletedAt: null },
      select: {
        id: true,
        email: true,
        fullName: true,
        avatarUrl: true,
        phoneNumber: true,
        isActive: true,
        twoFactorEnabled: true,
        mustChangePassword: true,
        createdAt: true,
        roleId: true,
        role: {
          select: {
            id: true,
            name: true,
          },
        },
      },
    });
  }

  async saveRefreshToken(
    userId: string,
    token: string,
    expiresAt: Date,
    userAgent?: string,
    ipAddress?: string,
  ) {
    return prisma.refreshToken.create({
      data: {
        userId,
        token: hashToken(token), // Lưu hash, không lưu plain-text
        expiresAt,
        userAgent,
        ipAddress,
      },
    });
  }

  async findRefreshToken(token: string) {
    return prisma.refreshToken.findUnique({
      where: { token: hashToken(token) },
    });
  }

  async deleteRefreshToken(token: string) {
    return prisma.refreshToken.deleteMany({
      where: { token: hashToken(token) },
    });
  }

  async findBySocial(provider: string, providerUserId: string) {
    const socialAccount = await prisma.userSocial.findUnique({
      where: {
        provider_providerUserId: {
          provider,
          providerUserId,
        },
      },
      include: {
        user: {
          include: { role: true },
        },
      },
    });
    return socialAccount?.user || null;
  }

  async createSocialUser(data: {
    email?: string;
    fullName?: string;
    avatarUrl?: string;
    roleId: string;
    provider: string;
    providerUserId: string;
  }) {
    return prisma.user.create({
      data: {
        email: data.email,
        fullName: data.fullName,
        avatarUrl: data.avatarUrl,
        roleId: data.roleId,
        isActive: true, // Social users are active immediately
        socialAccounts: {
          create: {
            provider: data.provider,
            providerUserId: data.providerUserId,
          },
        },
      },
      include: { role: true },
    });
  }

  async linkSocialAccount(
    userId: string,
    provider: string,
    providerUserId: string,
  ) {
    return prisma.userSocial.create({
      data: {
        userId,
        provider,
        providerUserId,
      },
    });
  }

  async linkAndActivateSocialUser(
    userId: string,
    provider: string,
    providerUserId: string,
    options?: { clearPassword?: boolean },
  ) {
    return prisma.$transaction(async (tx) => {
      await tx.userSocial.create({
        data: {
          userId,
          provider,
          providerUserId,
        },
      });
      return tx.user.update({
        where: { id: userId },
        data: {
          isActive: true,
          ...(options?.clearPassword ? { password: null } : {}),
        },
        include: { role: true },
      });
    }, DEFAULT_TRANSACTION_OPTIONS);
  }

  async getUserSocialAccounts(userId: string) {
    return prisma.userSocial.findMany({
      where: { userId },
      select: {
        id: true,
        provider: true,
        providerUserId: true,
        createdAt: true,
      },
      orderBy: { createdAt: "desc" },
    });
  }

  async findUserSocialByProvider(userId: string, provider: string) {
    return prisma.userSocial.findFirst({
      where: { userId, provider },
    });
  }

  async unlinkSocialAccount(userId: string, provider: string) {
    return prisma.userSocial.deleteMany({
      where: { userId, provider },
    });
  }

  async countUserSocialAccounts(userId: string): Promise<number> {
    return prisma.userSocial.count({
      where: { userId },
    });
  }

  async createVerificationToken(
    userId: string,
    token: string,
    expiresAt: Date,
    afterCreate?: (tx: Prisma.TransactionClient) => Promise<void>,
  ) {
    return prisma.$transaction(async (tx) => {
      await tx.verificationToken.deleteMany({
        where: { userId, type: VERIFICATION_TOKEN_TYPE.EMAIL_VERIFICATION },
      });
      const created = await tx.verificationToken.create({
        data: {
          userId,
          token: hashToken(token), // Lưu hash
          type: VERIFICATION_TOKEN_TYPE.EMAIL_VERIFICATION,
          expiresAt,
        },
      });
      if (afterCreate) {
        await afterCreate(tx);
      }
      return created;
    }, DEFAULT_TRANSACTION_OPTIONS);
  }

  async findVerificationToken(token: string) {
    return prisma.verificationToken.findUnique({
      where: { token: hashToken(token) },
      include: { user: true },
    });
  }

  async findActiveVerificationTokenByUserId(
    userId: string,
    type: string = VERIFICATION_TOKEN_TYPE.EMAIL_VERIFICATION,
  ) {
    return prisma.verificationToken.findFirst({
      where: {
        userId,
        type,
        expiresAt: { gt: new Date() },
      },
      orderBy: { createdAt: "desc" },
    });
  }

  async activateUser(userId: string) {
    return prisma.user.update({
      where: { id: userId },
      data: { isActive: true },
    });
  }

  async activateUserAndClearPassword(userId: string) {
    return prisma.user.update({
      where: { id: userId },
      data: { isActive: true, password: null },
    });
  }

  async deleteVerificationToken(tokenId: string) {
    return prisma.verificationToken.delete({
      where: { id: tokenId },
    });
  }

  async findRoleByName(name: string) {
    return prisma.role.findUnique({
      where: { name },
    });
  }

  async createUser(data: {
    email: string;
    passwordHash: string;
    fullName?: string;
    roleId: string;
    isActive: boolean;
  }) {
    return prisma.user.create({
      data: {
        email: data.email,
        password: data.passwordHash,
        fullName: data.fullName,
        roleId: data.roleId,
        isActive: data.isActive,
      },
    });
  }

  async findByPhone(phoneNumber: string) {
    return prisma.user.findFirst({
      where: { phoneNumber, deletedAt: null },
    });
  }

  async updateProfile(
    userId: string,
    data: { fullName?: string; avatarUrl?: string; phoneNumber?: string },
  ) {
    return prisma.user.update({
      where: { id: userId },
      data,
    });
  }

  async updatePassword(userId: string, passwordHash: string) {
    return prisma.user.update({
      where: { id: userId },
      data: {
        password: passwordHash,
        mustChangePassword: false,
        failedLoginAttempts: 0,
        lockedUntil: null,
      },
    });
  }

  async softDelete(userId: string, adminId: string) {
    return prisma.$transaction([
      prisma.user.update({
        where: { id: userId },
        data: {
          deletedAt: new Date(),
          deletedBy: adminId,
          isActive: false,
        },
      }),
      prisma.refreshToken.deleteMany({
        where: { userId },
      }),
    ]);
  }

  async createPasswordResetToken(
    userId: string,
    token: string,
    expiresAt: Date,
    afterCreate?: (tx: Prisma.TransactionClient) => Promise<void>,
  ) {
    return prisma.$transaction(async (tx) => {
      await tx.passwordResetToken.deleteMany({
        where: { userId },
      });
      const created = await tx.passwordResetToken.create({
        data: {
          userId,
          token: hashToken(token), // Lưu hash
          expiresAt,
        },
      });
      if (afterCreate) {
        await afterCreate(tx);
      }
      return created;
    }, DEFAULT_TRANSACTION_OPTIONS);
  }

  async findPasswordResetToken(token: string) {
    return prisma.passwordResetToken.findUnique({
      where: { token: hashToken(token) },
      include: { user: true },
    });
  }

  async findRecentPasswordResetToken(
    userId: string,
    withinSeconds: number = 60,
  ) {
    const threshold = new Date(Date.now() - withinSeconds * 1000);
    return prisma.passwordResetToken.findFirst({
      where: {
        userId,
        createdAt: { gte: threshold },
      },
    });
  }

  async deletePasswordResetToken(tokenId: string) {
    return prisma.passwordResetToken.delete({
      where: { id: tokenId },
    });
  }

  async findUserDevice(userId: string, deviceHash: string) {
    return prisma.userDevice.findUnique({
      where: {
        userId_deviceHash: {
          userId,
          deviceHash,
        },
      },
    });
  }

  async upsertUserDevice(data: {
    userId: string;
    deviceHash: string;
    deviceName: string;
    ipAddress?: string;
  }) {
    return prisma.userDevice.upsert({
      where: {
        userId_deviceHash: {
          userId: data.userId,
          deviceHash: data.deviceHash,
        },
      },
      update: {
        ipAddress: data.ipAddress,
        lastLoginAt: new Date(),
      },
      create: {
        userId: data.userId,
        deviceHash: data.deviceHash,
        deviceName: data.deviceName,
        ipAddress: data.ipAddress,
      },
    });
  }

  async updateUserDeviceLastLogin(
    userId: string,
    deviceHash: string,
    ipAddress?: string,
  ) {
    return prisma.userDevice.update({
      where: {
        userId_deviceHash: {
          userId,
          deviceHash,
        },
      },
      data: {
        ipAddress,
        lastLoginAt: new Date(),
      },
    });
  }

  async findSessionsByUserId(userId: string) {
    return prisma.refreshToken.findMany({
      where: { userId },
      orderBy: { createdAt: "desc" },
    });
  }

  async findSessionById(userId: string, sessionId: string) {
    return prisma.refreshToken.findFirst({
      where: { id: sessionId, userId },
    });
  }

  async deleteSessionById(userId: string, sessionId: string) {
    return prisma.refreshToken.deleteMany({
      where: { id: sessionId, userId },
    });
  }

  async rotateRefreshToken(
    userId: string,
    oldToken: string,
    newToken: string,
    expiresAt: Date,
    userAgent?: string,
    ipAddress?: string,
  ): Promise<{ rotated: boolean; reason?: "EXPIRED" | "REUSED" }> {
    const hashedOldToken = hashToken(oldToken);
    const hashedNewToken = hashToken(newToken);
    return prisma.$transaction(async (tx) => {
      const existing = await tx.refreshToken.findUnique({
        where: { token: hashedOldToken },
      });

      if (!existing) {
        // Automatic Token Family Invalidation (RFC 6819):
        // If an already rotated/revoked refresh token is re-sent, invalidate all active tokens for this user
        await tx.refreshToken.deleteMany({ where: { userId } });
        return { rotated: false, reason: "REUSED" };
      }

      if (existing.expiresAt < new Date()) {
        await tx.refreshToken.delete({ where: { id: existing.id } });
        return { rotated: false, reason: "EXPIRED" };
      }

      await tx.refreshToken.delete({ where: { id: existing.id } });
      await tx.refreshToken.create({
        data: {
          userId,
          token: hashedNewToken,
          expiresAt,
          userAgent,
          ipAddress,
        },
      });

      return { rotated: true };
    }, DEFAULT_TRANSACTION_OPTIONS);
  }

  async updatePasswordAndRevokeTokens(userId: string, passwordHash: string) {
    return prisma.$transaction([
      prisma.user.update({
        where: { id: userId },
        data: {
          password: passwordHash,
          mustChangePassword: false,
          failedLoginAttempts: 0,
          lockedUntil: null,
        },
      }),
      prisma.refreshToken.deleteMany({
        where: { userId },
      }),
    ]);
  }

  async registerUserWithVerification(
    userData: {
      email: string;
      passwordHash: string;
      fullName?: string | null;
      roleId: string;
      isActive: boolean;
      phoneNumber?: string | null;
    },
    token: string,
    expiresAt: Date,
    afterCreate?: (
      tx: Prisma.TransactionClient,
      user: { id: string; email: string | null; fullName: string | null },
    ) => Promise<void>,
  ) {
    return prisma.$transaction(async (tx) => {
      const user = await tx.user.create({
        data: {
          email: userData.email,
          password: userData.passwordHash,
          fullName: userData.fullName,
          phoneNumber: userData.phoneNumber,
          roleId: userData.roleId,
          isActive: userData.isActive,
        },
      });
      await tx.verificationToken.create({
        data: {
          userId: user.id,
          token: hashToken(token), // Lưu hash
          expiresAt,
        },
      });
      if (afterCreate) {
        await afterCreate(tx, user);
      }
      return user;
    }, DEFAULT_TRANSACTION_OPTIONS);
  }

  async activateUserAndDeleteToken(userId: string, tokenId: string) {
    return prisma.$transaction([
      prisma.user.update({
        where: { id: userId },
        data: { isActive: true },
      }),
      prisma.verificationToken.delete({
        where: { id: tokenId },
      }),
    ]);
  }

  async resetPasswordAndRevokeTokens(
    userId: string,
    passwordHash: string,
    tokenId: string,
  ) {
    return prisma.$transaction([
      prisma.user.update({
        where: { id: userId },
        data: {
          password: passwordHash,
          mustChangePassword: false,
          failedLoginAttempts: 0,
          lockedUntil: null,
        },
      }),
      prisma.passwordResetToken.delete({
        where: { id: tokenId },
      }),
      prisma.refreshToken.deleteMany({
        where: { userId },
      }),
    ]);
  }

  async updateLockout(
    userId: string,
    data: { failedLoginAttempts: number; lockedUntil: Date | null },
  ) {
    return prisma.user.update({
      where: { id: userId },
      data,
    });
  }

  async deleteOtherSessions(userId: string, currentToken: string) {
    const hashedCurrentToken = hashToken(currentToken);
    return prisma.refreshToken.deleteMany({
      where: {
        userId,
        NOT: {
          token: hashedCurrentToken,
        },
      },
    });
  }

  async countActiveAdmins(roleName: string = ROLES.ADMIN): Promise<number> {
    // 1. Tìm các role IDs có tư cách Admin (theo tên hoặc theo quyền gán role/permission)
    const adminRoles = await prisma.role.findMany({
      where: {
        OR: [
          { name: roleName },
          {
            permissions: {
              some: {
                permission: {
                  name: {
                    in: [
                      PERMISSIONS.USER_ROLE_ASSIGN,
                      PERMISSIONS.ROLE_PERMISSION_ASSIGN,
                    ],
                  },
                },
              },
            },
          },
        ],
      },
      select: { id: true },
    });

    const adminRoleIds = adminRoles.map((r) => r.id);
    if (adminRoleIds.length === 0) {
      return 0;
    }

    // 2. Tận dụng composite index @@index([roleId, isActive, deletedAt]) trên bảng User
    return prisma.user.count({
      where: {
        roleId: { in: adminRoleIds },
        isActive: true,
        deletedAt: null,
      },
    });
  }

  async createDeactivationToken(
    userId: string,
    token: string,
    expiresAt: Date,
    afterCreate?: (tx: Prisma.TransactionClient) => Promise<void>,
  ) {
    const hashedToken = hashToken(`deactivate:${token}`);
    return prisma.$transaction(async (tx) => {
      await tx.verificationToken.deleteMany({
        where: { userId, type: VERIFICATION_TOKEN_TYPE.DEACTIVATION },
      });
      const created = await tx.verificationToken.create({
        data: {
          userId,
          token: hashedToken,
          type: VERIFICATION_TOKEN_TYPE.DEACTIVATION,
          expiresAt,
        },
      });
      if (afterCreate) {
        await afterCreate(tx);
      }
      return created;
    }, DEFAULT_TRANSACTION_OPTIONS);
  }

  async findDeactivationToken(token: string) {
    const hashedToken = hashToken(`deactivate:${token}`);
    return prisma.verificationToken.findUnique({
      where: { token: hashedToken },
      include: {
        user: {
          include: { role: true },
        },
      },
    });
  }

  async deactivateUserAndRevokeSessions(userId: string, tokenId: string) {
    return prisma.$transaction([
      prisma.user.update({
        where: { id: userId },
        data: {
          isActive: false,
          deletedAt: new Date(),
          deletedBy: userId,
        },
      }),
      prisma.refreshToken.deleteMany({
        where: { userId },
      }),
      prisma.verificationToken.delete({
        where: { id: tokenId },
      }),
    ]);
  }

  createAuditLog(data: {
    actorId?: string;
    action: string;
    targetType: string;
    targetId: string;
    details?: Record<string, unknown> | null;
    ipAddress?: string;
    userAgent?: string;
  }) {
    return prisma.auditLog.create({
      data: {
        actorId: data.actorId,
        action: data.action,
        targetType: data.targetType,
        targetId: data.targetId,
        details: (data.details ?? undefined) as
          Prisma.InputJsonValue | undefined,
        ipAddress: data.ipAddress,
        userAgent: data.userAgent,
      },
    });
  }

  async savePendingTwoFactorSecret(userId: string, encryptedSecret: string) {
    return prisma.user.update({
      where: { id: userId },
      data: {
        twoFactorSecret: encryptedSecret,
      },
    });
  }

  async enable2FA(
    userId: string,
    encryptedSecret: string,
    hashedBackupCodes: string[],
  ) {
    return prisma.user.update({
      where: { id: userId },
      data: {
        twoFactorEnabled: true,
        twoFactorSecret: encryptedSecret,
        twoFactorBackupCodes: hashedBackupCodes,
      },
    });
  }

  async disable2FA(userId: string) {
    return prisma.user.update({
      where: { id: userId },
      data: {
        twoFactorEnabled: false,
        twoFactorSecret: null,
        twoFactorBackupCodes: Prisma.DbNull,
      },
    });
  }

  async enable2FAAndRevokeOtherSessions(
    userId: string,
    encryptedSecret: string,
    hashedBackupCodes: string[],
    currentRefreshToken?: string,
  ) {
    return prisma.$transaction(async (tx) => {
      const user = await tx.user.update({
        where: { id: userId },
        data: {
          twoFactorEnabled: true,
          twoFactorSecret: encryptedSecret,
          twoFactorBackupCodes: hashedBackupCodes,
        },
      });

      if (currentRefreshToken) {
        const hashedCurrentToken = hashToken(currentRefreshToken);
        await tx.refreshToken.deleteMany({
          where: {
            userId,
            NOT: {
              token: hashedCurrentToken,
            },
          },
        });
      } else {
        const latestSession = await tx.refreshToken.findFirst({
          where: { userId },
          orderBy: { createdAt: "desc" },
          select: { id: true },
        });

        if (latestSession) {
          await tx.refreshToken.deleteMany({
            where: {
              userId,
              id: { not: latestSession.id },
            },
          });
        }
      }

      return user;
    }, DEFAULT_TRANSACTION_OPTIONS);
  }

  async disable2FAAndRevokeOtherSessions(
    userId: string,
    currentRefreshToken?: string,
  ) {
    return prisma.$transaction(async (tx) => {
      const user = await tx.user.update({
        where: { id: userId },
        data: {
          twoFactorEnabled: false,
          twoFactorSecret: null,
          twoFactorBackupCodes: Prisma.DbNull,
        },
      });

      if (currentRefreshToken) {
        const hashedCurrentToken = hashToken(currentRefreshToken);
        await tx.refreshToken.deleteMany({
          where: {
            userId,
            NOT: {
              token: hashedCurrentToken,
            },
          },
        });
      } else {
        const latestSession = await tx.refreshToken.findFirst({
          where: { userId },
          orderBy: { createdAt: "desc" },
          select: { id: true },
        });

        if (latestSession) {
          await tx.refreshToken.deleteMany({
            where: {
              userId,
              id: { not: latestSession.id },
            },
          });
        }
      }

      return user;
    }, DEFAULT_TRANSACTION_OPTIONS);
  }

  async updateBackupCodes(userId: string, hashedBackupCodes: string[]) {
    return prisma.user.update({
      where: { id: userId },
      data: {
        twoFactorBackupCodes: hashedBackupCodes,
      },
    });
  }

  async revokeOtherSessions(userId: string, currentRefreshToken?: string) {
    if (currentRefreshToken) {
      const hashedCurrentToken = hashToken(currentRefreshToken);
      return prisma.refreshToken.deleteMany({
        where: {
          userId,
          NOT: {
            token: hashedCurrentToken,
          },
        },
      });
    }

    const latestSession = await prisma.refreshToken.findFirst({
      where: { userId },
      orderBy: { createdAt: "desc" },
      select: { id: true },
    });

    if (latestSession) {
      return prisma.refreshToken.deleteMany({
        where: {
          userId,
          id: { not: latestSession.id },
        },
      });
    }

    return { count: 0 };
  }

  async revokeAllUserSessions(userId: string) {
    return prisma.refreshToken.deleteMany({
      where: { userId },
    });
  }
}

export const authRepository = new AuthRepository();
