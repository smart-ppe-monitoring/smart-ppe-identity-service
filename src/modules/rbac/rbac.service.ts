import { RbacRepository } from "./rbac.repository";
import { userRepository } from "../users/user.repository";
import { AppError } from "../../common/errors/app-error";
import { ERROR_CODE } from "../../common/errors/error-code";
import {
  CreateRoleDto,
  UpdateRoleDto,
  RoleQueryDto,
  AuditLogQueryDto,
} from "./rbac.dto";
import { permissionCacheService } from "../../common/services/permission-cache.service";
import { ROLES } from "../../common/constants/role.constant";
import { PERMISSIONS } from "../../common/constants/permission.constant";
import {
  AUDIT_ACTION,
  AUDIT_TARGET_TYPE,
} from "../../common/constants/audit-log.constant";
import {
  NOTIFICATION_TYPE,
  NOTIFICATION_PRIORITY,
} from "../../common/constants/notification.constant";
import { notificationDispatcher } from "../../common/services/notification-dispatcher.service";

export class RbacService {
  private readonly repository: RbacRepository;

  constructor(repository?: RbacRepository) {
    this.repository = repository || new RbacRepository();
  }

  private async getRolePermissionAssignId(): Promise<string | null> {
    const perm = await this.repository.findPermissionByName(
      PERMISSIONS.ROLE_PERMISSION_ASSIGN,
    );
    return perm?.id ?? null;
  }

  private async findUserForRoleCheck(userId: string) {
    if (typeof (this.repository as any)?.findUserById === "function") {
      return (this.repository as any).findUserById(userId);
    }
    return userRepository.findUserWithRole(userId);
  }

  private async assignRoleForUser(userId: string, roleId: string) {
    if (typeof (this.repository as any)?.assignUserRole === "function") {
      return (this.repository as any).assignUserRole(userId, roleId);
    }
    return userRepository.assignRole(userId, roleId);
  }

  async findAllRoles(query: RoleQueryDto) {
    return this.repository.findAllRoles(query);
  }

  async findRoleById(id: string) {
    const role = await this.repository.findRoleById(id);
    if (!role) {
      throw new AppError("Role not found", 404, ERROR_CODE.NOT_FOUND);
    }
    return role;
  }

  async createRole(
    data: CreateRoleDto,
    context?: { actorId?: string; ipAddress?: string; userAgent?: string },
  ) {
    const existing = await this.repository.findRoleByName(data.name);
    if (existing) {
      throw new AppError(
        `Role with name '${data.name}' already exists`,
        409,
        ERROR_CODE.DUPLICATE_ENTRY,
      );
    }

    if (data.permissionIds && data.permissionIds.length > 0) {
      const validPermissions = await this.repository.findPermissionsByIds(
        data.permissionIds,
      );
      if (validPermissions.length !== data.permissionIds.length) {
        throw new AppError(
          "One or more permission IDs are invalid",
          400,
          ERROR_CODE.VALIDATION_ERROR,
        );
      }

      if (context?.actorId) {
        const actor = await this.findUserForRoleCheck(context.actorId);
        const isActorAdmin = actor?.role?.name === ROLES.ADMIN;

        if (!isActorAdmin) {
          const actorPermissions = actor?.roleId
            ? await permissionCacheService.getRolePermissions(actor.roleId)
            : new Set<string>();

          const unauthorizedPerms = validPermissions.filter(
            (p) => !actorPermissions.has(p.name),
          );

          if (unauthorizedPerms.length > 0) {
            throw new AppError(
              "Bạn không thể gán các quyền vượt quá tập quyền hiện có của vai trò bạn đang sở hữu (Subset Validation)",
              403,
              ERROR_CODE.FORBIDDEN,
            );
          }

          const hasDelegationPerm = validPermissions.some(
            (p) =>
              p.name === PERMISSIONS.ROLE_PERMISSION_ASSIGN ||
              p.name === PERMISSIONS.USER_ROLE_ASSIGN,
          );
          if (hasDelegationPerm) {
            throw new AppError(
              "Chỉ Quản trị viên (Admin) mới có quyền cấp các đặc quyền quản trị vai trò và phân quyền",
              403,
              ERROR_CODE.FORBIDDEN,
            );
          }
        }
      }
    }

    const role = await this.repository.createRole(data);

    await this.repository.createAuditLog({
      actorId: context?.actorId,
      action: AUDIT_ACTION.CREATE_ROLE,
      targetType: AUDIT_TARGET_TYPE.ROLE,
      targetId: role.id,
      details: {
        name: role.name,
        description: role.description,
        permissionsCount: data.permissionIds?.length || 0,
      },
      ipAddress: context?.ipAddress,
      userAgent: context?.userAgent,
    });

    return this.findRoleById(role.id);
  }

  async updateRole(
    id: string,
    data: UpdateRoleDto,
    context?: { actorId?: string; ipAddress?: string; userAgent?: string },
  ) {
    const role = await this.findRoleById(id);

    if (data.name && data.name !== role.name) {
      if (role.isSystem) {
        throw new AppError(
          `Cannot rename system role '${role.name}'`,
          400,
          ERROR_CODE.VALIDATION_ERROR,
        );
      }

      const existing = await this.repository.findRoleByName(data.name);
      if (existing && existing.id !== id) {
        throw new AppError(
          `Role with name '${data.name}' already exists`,
          409,
          ERROR_CODE.DUPLICATE_ENTRY,
        );
      }
    }

    const updated = await this.repository.updateRole(id, data);
    permissionCacheService.invalidateRole(id);

    await this.repository.createAuditLog({
      actorId: context?.actorId,
      action: AUDIT_ACTION.UPDATE_ROLE,
      targetType: AUDIT_TARGET_TYPE.ROLE,
      targetId: id,
      details: {
        previous: { name: role.name, description: role.description },
        updated: data,
      },
      ipAddress: context?.ipAddress,
      userAgent: context?.userAgent,
    });

    return this.findRoleById(updated.id);
  }

  async deleteRole(
    id: string,
    context?: { actorId?: string; ipAddress?: string; userAgent?: string },
  ) {
    const role = await this.findRoleById(id);

    if (role.isSystem) {
      throw new AppError(
        `Cannot delete system role '${role.name}'`,
        400,
        ERROR_CODE.VALIDATION_ERROR,
      );
    }

    if (role.userCount > 0) {
      throw new AppError(
        `Cannot delete role '${role.name}' because it currently has ${role.userCount} assigned users. Reassign users first.`,
        400,
        ERROR_CODE.VALIDATION_ERROR,
      );
    }

    await this.repository.deleteRole(id);
    permissionCacheService.invalidateRole(id);

    await this.repository.createAuditLog({
      actorId: context?.actorId,
      action: AUDIT_ACTION.DELETE_ROLE,
      targetType: AUDIT_TARGET_TYPE.ROLE,
      targetId: id,
      details: { name: role.name },
      ipAddress: context?.ipAddress,
      userAgent: context?.userAgent,
    });
  }

  async findAllPermissions(query?: {
    page?: number;
    limit?: number;
    resource?: string;
  }) {
    return this.repository.findAllPermissions(query);
  }

  async syncRolePermissions(
    roleId: string,
    permissionIds: string[],
    context?: { actorId?: string; ipAddress?: string; userAgent?: string },
  ) {
    const role = await this.findRoleById(roleId);

    const validPermissions =
      await this.repository.findPermissionsByIds(permissionIds);
    if (validPermissions.length !== permissionIds.length) {
      throw new AppError(
        "One or more permission IDs are invalid",
        400,
        ERROR_CODE.VALIDATION_ERROR,
      );
    }

    if (context?.actorId) {
      const actor = await this.findUserForRoleCheck(context.actorId);
      const isActorAdmin = actor?.role?.name === ROLES.ADMIN;

      // 1. Anti-privilege escalation: Only ADMIN can modify permissions of the ADMIN role
      if (role.name === ROLES.ADMIN && !isActorAdmin) {
        throw new AppError(
          "Chỉ Quản trị viên (Admin) mới có quyền chỉnh sửa quyền của vai trò Quản trị viên",
          403,
          ERROR_CODE.FORBIDDEN,
        );
      }

      // 2. Anti-self-escalation: Non-admin actors cannot alter their own role's permissions
      if (!isActorAdmin && actor?.roleId === roleId) {
        throw new AppError(
          "Không được phép tự gán hoặc thay đổi quyền cho vai trò của chính mình",
          403,
          ERROR_CODE.FORBIDDEN,
        );
      }

      // 3. Subset validation: Non-admin actors can only assign permissions they already possess
      if (!isActorAdmin) {
        const actorPermissions = actor?.roleId
          ? await permissionCacheService.getRolePermissions(actor.roleId)
          : new Set<string>();

        const unauthorizedPerms = validPermissions.filter(
          (p) => !actorPermissions.has(p.name),
        );

        if (unauthorizedPerms.length > 0) {
          throw new AppError(
            "Bạn không thể gán các quyền vượt quá tập quyền hiện có của vai trò bạn đang sở hữu (Subset Validation)",
            403,
            ERROR_CODE.FORBIDDEN,
          );
        }

        const hasDelegationPerm = validPermissions.some(
          (p) =>
            p.name === PERMISSIONS.ROLE_PERMISSION_ASSIGN ||
            p.name === PERMISSIONS.USER_ROLE_ASSIGN,
        );
        if (hasDelegationPerm) {
          throw new AppError(
            "Chỉ Quản trị viên (Admin) mới có quyền cấp các đặc quyền quản trị vai trò và phân quyền",
            403,
            ERROR_CODE.FORBIDDEN,
          );
        }
      }
    }

    // Anti-lockout protection: ADMIN role must retain ROLE_PERMISSION_ASSIGN
    if (role.name === ROLES.ADMIN) {
      const assignPermId = await this.getRolePermissionAssignId();
      if (assignPermId && !permissionIds.includes(assignPermId)) {
        throw new AppError(
          "Security Violation: Cannot revoke ROLE_PERMISSION_ASSIGN permission from the ADMIN role.",
          400,
          ERROR_CODE.VALIDATION_ERROR,
        );
      }
    }

    await this.repository.syncRolePermissions(roleId, permissionIds);
    permissionCacheService.invalidateRole(roleId);

    await this.repository.createAuditLog({
      actorId: context?.actorId,
      action: AUDIT_ACTION.SYNC_ROLE_PERMISSIONS,
      targetType: AUDIT_TARGET_TYPE.ROLE,
      targetId: roleId,
      details: {
        roleName: role.name,
        previousCount: role.permissions.length,
        newCount: permissionIds.length,
      },
      ipAddress: context?.ipAddress,
      userAgent: context?.userAgent,
    });

    return this.findRoleById(roleId);
  }

  async removePermissionFromRole(
    roleId: string,
    permissionId: string,
    context?: { actorId?: string; ipAddress?: string; userAgent?: string },
  ) {
    const role = await this.findRoleById(roleId);

    if (context?.actorId) {
      const actor = await this.findUserForRoleCheck(context.actorId);
      const isActorAdmin = actor?.role?.name === ROLES.ADMIN;

      // Anti-privilege escalation: ADMIN role can only be modified by an ADMIN
      if (role.name === ROLES.ADMIN && !isActorAdmin) {
        throw new AppError(
          "Chỉ Quản trị viên (Admin) mới có quyền chỉnh sửa quyền của vai trò Quản trị viên",
          403,
          ERROR_CODE.FORBIDDEN,
        );
      }

      // Anti-self-escalation: Non-admin actors cannot alter their own role's permissions
      if (!isActorAdmin && actor?.roleId === roleId) {
        throw new AppError(
          "Không được phép tự thay đổi quyền cho vai trò của chính mình",
          403,
          ERROR_CODE.FORBIDDEN,
        );
      }
    }

    // Anti-lockout protection: ADMIN role must retain ROLE_PERMISSION_ASSIGN
    if (role.name === ROLES.ADMIN) {
      const assignPermId = await this.getRolePermissionAssignId();
      if (assignPermId && assignPermId === permissionId) {
        throw new AppError(
          "Security Violation: Cannot revoke ROLE_PERMISSION_ASSIGN permission from the ADMIN role.",
          400,
          ERROR_CODE.VALIDATION_ERROR,
        );
      }
    }

    await this.repository.removePermissionFromRole(roleId, permissionId);
    permissionCacheService.invalidateRole(roleId);

    await this.repository.createAuditLog({
      actorId: context?.actorId,
      action: AUDIT_ACTION.REMOVE_ROLE_PERMISSION,
      targetType: AUDIT_TARGET_TYPE.ROLE,
      targetId: roleId,
      details: { roleName: role.name, permissionId },
      ipAddress: context?.ipAddress,
      userAgent: context?.userAgent,
    });

    return this.findRoleById(roleId);
  }

  async assignUserRole(
    userId: string,
    newRoleId: string,
    context?: { actorId?: string; ipAddress?: string; userAgent?: string },
  ) {
    if (context?.actorId && context.actorId === userId) {
      throw new AppError(
        "Bạn không thể tự thay đổi vai trò của chính mình",
        400,
        ERROR_CODE.VALIDATION_ERROR,
      );
    }

    const targetRole = await this.findRoleById(newRoleId);
    const currentUser = await this.findUserForRoleCheck(userId);
    if (!currentUser) {
      throw new AppError("User not found", 404, ERROR_CODE.NOT_FOUND);
    }

    const targetPermissions = await permissionCacheService.getRolePermissions(
      targetRole.id,
    );
    const isTargetAdmin =
      targetRole.name === ROLES.ADMIN ||
      targetPermissions.has(PERMISSIONS.USER_ROLE_ASSIGN) ||
      targetPermissions.has(PERMISSIONS.ROLE_PERMISSION_ASSIGN);

    // Privilege escalation guard: Chỉ Quản trị viên mới có quyền cấp vai trò Quản trị viên cho người dùng
    if (isTargetAdmin && context?.actorId) {
      const actor = await this.findUserForRoleCheck(context.actorId);
      const actorPermissions = actor?.roleId
        ? await permissionCacheService.getRolePermissions(actor.roleId)
        : new Set<string>();
      const isActorAdmin =
        actor?.role?.name === ROLES.ADMIN ||
        actorPermissions.has(PERMISSIONS.USER_ROLE_ASSIGN) ||
        actorPermissions.has(PERMISSIONS.ROLE_PERMISSION_ASSIGN);

      if (!isActorAdmin) {
        throw new AppError(
          "Chỉ Quản trị viên (Admin) mới có quyền cấp vai trò Quản trị viên cho người dùng",
          403,
          ERROR_CODE.FORBIDDEN,
        );
      }
    }

    // Anti-lockout guard: Ngăn chặn hạ quyền Quản trị viên (Admin) duy nhất
    if (
      currentUser.isActive &&
      !currentUser.deletedAt &&
      currentUser.roleId !== targetRole.id
    ) {
      const currentPermissions = currentUser.roleId
        ? await permissionCacheService.getRolePermissions(currentUser.roleId)
        : new Set<string>();
      const isCurrentAdmin =
        currentUser.role?.name === ROLES.ADMIN ||
        currentPermissions.has(PERMISSIONS.USER_ROLE_ASSIGN) ||
        currentPermissions.has(PERMISSIONS.ROLE_PERMISSION_ASSIGN);

      if (isCurrentAdmin && !isTargetAdmin) {
        const activeAdminsCount = await userRepository.countActiveAdmins(
          currentUser.role?.name,
        );
        if (activeAdminsCount <= 1) {
          throw new AppError(
            "Không thể hạ quyền Quản trị viên (Admin) duy nhất trong hệ thống",
            400,
            ERROR_CODE.VALIDATION_ERROR,
          );
        }
      }
    }

    const oldRoleId = currentUser.roleId;

    const user = await this.assignRoleForUser(userId, targetRole.id);
    if (oldRoleId && oldRoleId !== targetRole.id) {
      permissionCacheService.invalidateRole(oldRoleId);
    }
    permissionCacheService.invalidateRole(user.roleId);
    permissionCacheService.invalidateUser(userId);

    await this.repository.createAuditLog({
      actorId: context?.actorId,
      action: AUDIT_ACTION.ASSIGN_USER_ROLE,
      targetType: AUDIT_TARGET_TYPE.USER,
      targetId: userId,
      details: { userEmail: user.email, assignedRole: targetRole.name },
      ipAddress: context?.ipAddress,
      userAgent: context?.userAgent,
    });

    // Thông báo cho user biết vai trò của họ vừa được cập nhật
    notificationDispatcher
      .notify(
        userId,
        NOTIFICATION_TYPE.INFO,
        "Cập nhật vai trò tài khoản",
        `Vai trò tài khoản của bạn đã được cập nhật thành: ${targetRole.name}.`,
        { priority: NOTIFICATION_PRIORITY.HIGH },
      )
      .catch((err: any) => console.error("Failed to notify role assignment:", err));

    return user;
  }

  async findAllAuditLogs(query: AuditLogQueryDto) {
    if (
      query.search?.trim() &&
      typeof this.repository.searchAuditLogsFts === "function"
    ) {
      return this.repository.searchAuditLogsFts(query);
    }
    return this.repository.findAllAuditLogs(query);
  }
}
