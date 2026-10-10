import crypto from "node:crypto";
import bcrypt from "bcryptjs";
import { UserRepository } from "./user.repository";
import { AppError } from "../../common/errors/app-error";
import { ERROR_CODE } from "../../common/errors/error-code";
import {
  AUDIT_ACTION,
  AUDIT_TARGET_TYPE,
} from "../../common/constants/audit-log.constant";
import { ROLES } from "../../common/constants/role.constant";
import { PERMISSIONS } from "../../common/constants/permission.constant";
import { parseUserAgent } from "../../common/helpers/user-agent.helper";
import { permissionCacheService } from "../../common/services/permission-cache.service";
import {
  UserQueryDto,
  CreateUserDto,
  UpdateUserDto,
  AdminResetPasswordDto,
  AdminResetPasswordResponseDto,
} from "./user.dto";
import {
  eventBus,
  EventBusService,
} from "../../common/services/event-bus.service";
import { EVENT_NAMES } from "../../common/constants/event.constant";

export class UserService {
  private readonly repository: UserRepository;
  private readonly eventBus: EventBusService;

  constructor(repository?: UserRepository, eventBusService?: EventBusService) {
    this.repository = repository || new UserRepository();
    this.eventBus = eventBusService || eventBus;
  }

  /**
   * Kiểm tra người dùng có giữ vai trò hoặc đặc quyền quản trị hệ thống hay không:
   * 1. Có tên vai trò khớp với ROLES.ADMIN
   * 2. Hoặc vai trò sở hữu các quyền quản trị then chốt (USER_ROLE_ASSIGN, ROLE_PERMISSION_ASSIGN)
   */
  async isAdministrativeUser(user: {
    roleId?: string | null;
    role?: { name: string } | null;
  }): Promise<boolean> {
    if (user.role?.name === ROLES.ADMIN) {
      return true;
    }
    if (user.roleId) {
      const permissions = await permissionCacheService.getRolePermissions(
        user.roleId,
      );
      return (
        permissions.has(PERMISSIONS.USER_ROLE_ASSIGN) ||
        permissions.has(PERMISSIONS.ROLE_PERMISSION_ASSIGN)
      );
    }
    return false;
  }

  async findAll(query: UserQueryDto) {
    if (
      query.search?.trim() &&
      typeof this.repository.searchFts === "function"
    ) {
      return this.repository.searchFts(query);
    }
    return this.repository.findAll(query);
  }

  async findById(id: string) {
    const user = await this.repository.findById(id);

    if (!user) {
      throw new AppError("User not found", 404, ERROR_CODE.NOT_FOUND);
    }

    return user;
  }

  async create(data: CreateUserDto) {
    const existing = await this.repository.findByEmail(data.email);

    if (existing) {
      throw new AppError(
        "Email already in use",
        409,
        ERROR_CODE.DUPLICATE_ENTRY,
      );
    }

    const passwordHash = await bcrypt.hash(data.password, 10);

    return this.repository.create({
      email: data.email,
      passwordHash,
      roleId: data.roleId,
      fullName: data.fullName,
      phoneNumber: data.phoneNumber,
      isActive: true, // Admin-created users are active by default
      mustChangePassword: data.mustChangePassword ?? true,
    });
  }

  async update(id: string, data: UpdateUserDto, actorId?: string) {
    const existing = await this.findById(id);

    const isTargetAdmin = await this.isAdministrativeUser(existing);

    // Vertical hierarchy check: Only administrative users can modify other administrative users
    if (isTargetAdmin && actorId && actorId !== id) {
      const actor = await this.findById(actorId);
      const isActorAdmin = await this.isAdministrativeUser(actor);
      if (!isActorAdmin) {
        throw new AppError(
          "Bạn không có quyền chỉnh sửa tài khoản Quản trị viên (Admin)",
          403,
          ERROR_CODE.FORBIDDEN,
        );
      }
    }

    // Anti-lockout guard: Ngăn chặn vô hiệu hóa Quản trị viên (Admin) duy nhất
    if (data.isActive === false && existing.isActive) {
      if (isTargetAdmin) {
        const activeAdminsCount = await this.repository.countActiveAdmins(
          existing.role?.name,
        );
        if (activeAdminsCount <= 1) {
          throw new AppError(
            "Không thể vô hiệu hóa Quản trị viên (Admin) duy nhất trong hệ thống",
            400,
            ERROR_CODE.VALIDATION_ERROR,
          );
        }
      }
    }

    // MED-01 Fix: Chặn mass assignment / trái phép thay đổi trạng thái tài khoản bởi non-admin
    if (
      data.isActive !== undefined &&
      data.isActive !== existing.isActive &&
      actorId
    ) {
      const actor = await this.findById(actorId);
      const isActorAdmin = await this.isAdministrativeUser(actor);
      if (!isActorAdmin) {
        throw new AppError(
          "Bạn không có quyền kích hoạt hoặc vô hiệu hóa tài khoản người dùng",
          403,
          ERROR_CODE.FORBIDDEN,
        );
      }
    }

    const updatePayload: {
      isActive?: boolean;
      fullName?: string;
      phoneNumber?: string;
    } = {};

    if (data.isActive !== undefined) updatePayload.isActive = data.isActive;
    if (data.fullName !== undefined) updatePayload.fullName = data.fullName;
    if (data.phoneNumber !== undefined)
      updatePayload.phoneNumber = data.phoneNumber;

    const updatedUser = await this.repository.update(id, updatePayload);

    permissionCacheService.invalidateUser(id);
    return updatedUser;
  }

  async softDelete(
    id: string,
    adminId: string,
    metadata?: { ipAddress?: string; userAgent?: string },
  ) {
    if (id === adminId) {
      throw new AppError(
        "Cannot delete your own account",
        400,
        ERROR_CODE.VALIDATION_ERROR,
      );
    }
    const userToDelete = await this.findById(id);

    // Vertical hierarchy check: Only administrative users can delete other administrative users
    const isTargetAdmin = await this.isAdministrativeUser(userToDelete);
    if (isTargetAdmin) {
      const actor = await this.findById(adminId);
      const isActorAdmin = await this.isAdministrativeUser(actor);
      if (!isActorAdmin) {
        throw new AppError(
          "Bạn không có quyền xóa tài khoản Quản trị viên (Admin)",
          403,
          ERROR_CODE.FORBIDDEN,
        );
      }
    }

    // Anti-lockout guard: Ngăn chặn xóa tài khoản Quản trị viên (Admin) duy nhất
    if (userToDelete.isActive && isTargetAdmin) {
      const activeAdminsCount = await this.repository.countActiveAdmins(
        userToDelete.role?.name,
      );
      if (activeAdminsCount <= 1) {
        throw new AppError(
          "Không thể xóa tài khoản Quản trị viên (Admin) duy nhất trong hệ thống",
          400,
          ERROR_CODE.VALIDATION_ERROR,
        );
      }
    }

    const result = await this.repository.softDelete(id, adminId);
    permissionCacheService.invalidateUser(id);

    await this.repository.createAuditLog({
      actorId: adminId,
      action: AUDIT_ACTION.DELETE_USER,
      targetType: AUDIT_TARGET_TYPE.USER,
      targetId: id,
      details: { deletedBy: adminId },
      ipAddress: metadata?.ipAddress,
      userAgent: metadata?.userAgent,
    });

    const [deletedUser] = result;
    const deletedAt = deletedUser?.deletedAt || new Date();

    // Event-Driven Backbone: Publish user.soft_deleted event
    await this.eventBus
      .publish(EVENT_NAMES.USER_SOFT_DELETED, {
        userId: id,
        deletedBy: adminId || null,
        deletedAt,
      })
      .catch((err) => {
        console.warn(
          "[UserService] Failed to publish user.soft_deleted event:",
          err?.message || err,
        );
      });

    return result;
  }

  async restore(
    id: string,
    adminId: string,
    metadata?: { ipAddress?: string; userAgent?: string },
  ) {
    const userToRestore = await this.repository.findWithDeleted(id);

    if (!userToRestore || !userToRestore.deletedAt) {
      throw new AppError(
        "Người dùng không ở trạng thái bị xóa",
        400,
        ERROR_CODE.BAD_REQUEST,
      );
    }

    // Vertical hierarchy check: Only administrative users can restore other administrative users
    const isTargetAdmin = await this.isAdministrativeUser(userToRestore);
    if (isTargetAdmin) {
      const actor = await this.findById(adminId);
      const isActorAdmin = await this.isAdministrativeUser(actor);
      if (!isActorAdmin) {
        throw new AppError(
          "Bạn không có quyền khôi phục tài khoản Quản trị viên (Admin)",
          403,
          ERROR_CODE.FORBIDDEN,
        );
      }
    }

    const restored = await this.repository.restore(id);
    permissionCacheService.invalidateUser(id);

    await this.repository.createAuditLog({
      actorId: adminId,
      action: AUDIT_ACTION.RESTORE_USER,
      targetType: AUDIT_TARGET_TYPE.USER,
      targetId: id,
      details: { restoredBy: adminId },
      ipAddress: metadata?.ipAddress,
      userAgent: metadata?.userAgent,
    });

    return restored;
  }

  async adminResetPassword(
    id: string,
    data: AdminResetPasswordDto,
    adminId: string,
    metadata?: { ipAddress?: string; userAgent?: string },
  ): Promise<AdminResetPasswordResponseDto> {
    const targetUser = await this.findById(id);

    // Vertical hierarchy check: Only administrative users can reset password for other administrative users
    const isTargetAdmin = await this.isAdministrativeUser(targetUser);
    if (isTargetAdmin && adminId !== id) {
      const actor = await this.findById(adminId);
      const isActorAdmin = await this.isAdministrativeUser(actor);
      if (!isActorAdmin) {
        throw new AppError(
          "Bạn không có quyền đặt lại mật khẩu cho Quản trị viên (Admin)",
          403,
          ERROR_CODE.FORBIDDEN,
        );
      }
    }

    const passwordToSet =
      data.newPassword || `Tmp@${crypto.randomBytes(4).toString("hex")}!9`;

    const passwordHash = await bcrypt.hash(passwordToSet, 10);
    const mustChangePassword = data.mustChangePassword ?? true;

    const result = await this.repository.adminResetPassword(
      id,
      passwordHash,
      mustChangePassword,
    );

    permissionCacheService.invalidateUser(id);

    await this.repository.createAuditLog({
      actorId: adminId,
      action: AUDIT_ACTION.ADMIN_RESET_PASSWORD,
      targetType: AUDIT_TARGET_TYPE.USER,
      targetId: id,
      details: { mustChangePassword, resetBy: adminId },
      ipAddress: metadata?.ipAddress,
      userAgent: metadata?.userAgent,
    });

    return {
      ...result,
      temporaryPassword: data.newPassword ? undefined : passwordToSet,
    };
  }

  // ────── Session Management ──────

  async getUserSessions(userId: string) {
    await this.findById(userId);
    const sessions = await this.repository.findSessionsByUserId(userId);
    return sessions.map((s) => ({
      id: s.id,
      deviceName: parseUserAgent(s.userAgent || undefined),
      ipAddress: s.ipAddress || "Không rõ",
      createdAt: s.createdAt,
      expiresAt: s.expiresAt,
    }));
  }

  async revokeUserSession(
    userId: string,
    sessionId: string,
    adminId?: string,
    metadata?: { ipAddress?: string; userAgent?: string },
  ) {
    const user = await this.findById(userId);
    const isTargetAdmin = await this.isAdministrativeUser(user);
    if (isTargetAdmin && adminId && adminId !== userId) {
      const actor = await this.findById(adminId);
      const isActorAdmin = await this.isAdministrativeUser(actor);
      if (!isActorAdmin) {
        throw new AppError(
          "Bạn không có quyền thu hồi phiên đăng nhập của Quản trị viên (Admin)",
          403,
          ERROR_CODE.FORBIDDEN,
        );
      }
    }

    const session = await this.repository.findSessionById(userId, sessionId);
    if (!session) {
      throw new AppError(
        "Phiên đăng nhập không tồn tại hoặc đã hết hạn",
        404,
        ERROR_CODE.NOT_FOUND,
      );
    }
    await this.repository.deleteSessionById(userId, sessionId);
    await this.repository.createAuditLog({
      actorId: adminId,
      action: AUDIT_ACTION.REVOKE_USER_SESSION,
      targetType: AUDIT_TARGET_TYPE.USER,
      targetId: userId,
      details: { sessionId },
      ipAddress: metadata?.ipAddress,
      userAgent: metadata?.userAgent,
    });
  }

  async revokeAllUserSessions(
    userId: string,
    adminId?: string,
    metadata?: { ipAddress?: string; userAgent?: string },
  ) {
    const user = await this.findById(userId);
    const isTargetAdmin = await this.isAdministrativeUser(user);
    if (isTargetAdmin && adminId && adminId !== userId) {
      const actor = await this.findById(adminId);
      const isActorAdmin = await this.isAdministrativeUser(actor);
      if (!isActorAdmin) {
        throw new AppError(
          "Bạn không có quyền thu hồi phiên đăng nhập của Quản trị viên (Admin)",
          403,
          ERROR_CODE.FORBIDDEN,
        );
      }
    }

    const deleted = await this.repository.deleteAllSessionsByUserId(userId);
    await this.repository.createAuditLog({
      actorId: adminId,
      action: AUDIT_ACTION.REVOKE_ALL_USER_SESSIONS,
      targetType: AUDIT_TARGET_TYPE.USER,
      targetId: userId,
      details: { revokedCount: deleted.count },
      ipAddress: metadata?.ipAddress,
      userAgent: metadata?.userAgent,
    });
    return { count: deleted.count };
  }

  // ────── Device Management ──────

  async getUserDevices(userId: string) {
    await this.findById(userId);
    const devices = await this.repository.findDevicesByUserId(userId);
    return devices.map((d) => ({
      id: d.id,
      deviceName: d.deviceName || "Thiết bị không rõ",
      ipAddress: d.ipAddress || "Không rõ",
      lastLoginAt: d.lastLoginAt,
      createdAt: d.createdAt,
    }));
  }

  async deleteUserDevice(
    userId: string,
    deviceId: string,
    adminId?: string,
    metadata?: { ipAddress?: string; userAgent?: string },
  ) {
    const user = await this.findById(userId);
    const isTargetAdmin = await this.isAdministrativeUser(user);
    if (isTargetAdmin && adminId && adminId !== userId) {
      const actor = await this.findById(adminId);
      const isActorAdmin = await this.isAdministrativeUser(actor);
      if (!isActorAdmin) {
        throw new AppError(
          "Bạn không có quyền xóa thiết bị của Quản trị viên (Admin)",
          403,
          ERROR_CODE.FORBIDDEN,
        );
      }
    }

    const device = await this.repository.findDeviceById(userId, deviceId);
    if (!device) {
      throw new AppError(
        "Thiết bị không tồn tại",
        404,
        ERROR_CODE.DEVICE_NOT_FOUND,
      );
    }
    await this.repository.deleteDeviceById(userId, deviceId);
    await this.repository.createAuditLog({
      actorId: adminId,
      action: AUDIT_ACTION.DELETE_USER_DEVICE,
      targetType: AUDIT_TARGET_TYPE.USER,
      targetId: userId,
      details: { deviceId, deviceName: device.deviceName },
      ipAddress: metadata?.ipAddress,
      userAgent: metadata?.userAgent,
    });
  }
}
