import { Request, Response, NextFunction } from "express";
import { AppError } from "../common/errors/app-error";
import { ERROR_CODE } from "../common/errors/error-code";
import { permissionCacheService } from "../common/services/permission-cache.service";
import { PERMISSIONS } from "../common/constants/permission.constant";
import { ROLES } from "../common/constants/role.constant";

async function resolveUserPermissions(req: Request): Promise<Set<string>> {
  if (!req.user) {
    throw new AppError("Unauthorized", 401, ERROR_CODE.UNAUTHORIZED);
  }

  let roleId = req.user.roleId;

  // 1. Xác thực trạng thái người dùng (cached 60s) để chống dùng JWT cũ khi bị khóa/hạ quyền
  // Bỏ qua khi request đã được xác thực qua API Key (đã có cơ chế kiểm tra riêng)
  if (!req.apiKey) {
    try {
      const currentUser = await permissionCacheService.getUserState(req.user.id);
      // Từ chối khi tài khoản không tồn tại, đã bị khóa hoặc xóa mềm
      if (currentUser !== undefined && (currentUser === null || !currentUser.isActive || currentUser.deletedAt)) {
        throw new AppError(
          "Tài khoản của bạn đã bị vô hiệu hóa hoặc không tồn tại",
          401,
          ERROR_CODE.UNAUTHORIZED,
        );
      }
      if (currentUser?.roleId) {
        roleId = currentUser.roleId;
        req.user.roleId = roleId;
      }
      if (currentUser?.roleName) {
        req.user.role = currentUser.roleName;
      }
    } catch (err) {
      if (err instanceof AppError) throw err;
      // Resilient Fallback: Nếu không kết nối được Identity DB, dùng roleId từ JWT đã verify
    }
  }

  let userPermissions = new Set<string>();

  // 2. Admin Bypass: ADMIN có toàn bộ quyền trong hệ thống (chỉ bypass sau khi đã xác thực trạng thái tài khoản)
  if (req.user.role === ROLES.ADMIN || req.user.role === "ADMIN") {
    userPermissions = new Set(Object.values(PERMISSIONS));
  } else {
    if (!roleId) {
      throw new AppError(
        "Forbidden: User role not found",
        403,
        ERROR_CODE.FORBIDDEN,
      );
    }

    try {
      userPermissions = await permissionCacheService.getRolePermissions(roleId);
    } catch {
      // Resilient Fallback theo Role khi mất kết nối Identity DB
      if (req.user.role === ROLES.SAFETY_MANAGER || req.user.role === "SAFETY_MANAGER") {
        userPermissions = new Set([
          PERMISSIONS.PPE_SITE_READ, PERMISSIONS.PPE_SITE_MANAGE,
          PERMISSIONS.PPE_ZONE_READ, PERMISSIONS.PPE_ZONE_MANAGE,
          PERMISSIONS.PPE_CAMERA_READ, PERMISSIONS.PPE_CAMERA_MANAGE,
          PERMISSIONS.PPE_SAFETY_CONFIG_READ, PERMISSIONS.PPE_SAFETY_CONFIG_MANAGE,
          PERMISSIONS.PPE_INCIDENT_READ, PERMISSIONS.PPE_INCIDENT_MANAGE,
          PERMISSIONS.PPE_REPORTING_READ, PERMISSIONS.PPE_REPORTING_EXPORT,
          PERMISSIONS.NOTIFICATION_READ, PERMISSIONS.NOTIFICATION_CREATE,
          PERMISSIONS.FILE_READ, PERMISSIONS.FILE_UPLOAD, PERMISSIONS.FILE_MANAGE,
        ]);
      } else if (req.user.role === ROLES.SAFETY_OFFICER || req.user.role === "SAFETY_OFFICER") {
        userPermissions = new Set([
          PERMISSIONS.PPE_SITE_READ,
          PERMISSIONS.PPE_ZONE_READ,
          PERMISSIONS.PPE_CAMERA_READ,
          PERMISSIONS.PPE_SAFETY_CONFIG_READ,
          PERMISSIONS.PPE_INCIDENT_READ, PERMISSIONS.PPE_INCIDENT_MANAGE,
          PERMISSIONS.PPE_REPORTING_READ,
          PERMISSIONS.NOTIFICATION_READ,
          PERMISSIONS.FILE_READ, PERMISSIONS.FILE_UPLOAD,
        ]);
      } else {
        userPermissions = new Set([
          PERMISSIONS.NOTIFICATION_READ,
          PERMISSIONS.FILE_READ,
        ]);
      }
    }
  }

  // If request is authenticated via API Key, intersect role permissions with scoped API Key permissions
  if (req.apiKey) {
    const keyPermsList = Array.isArray(req.apiKey.permissions)
      ? req.apiKey.permissions
      : Array.isArray(req.user.permissions)
        ? req.user.permissions
        : [];
    const apiKeyPermissions = new Set(keyPermsList);
    const effectivePermissions = new Set<string>();
    for (const perm of userPermissions) {
      if (apiKeyPermissions.has(perm)) {
        effectivePermissions.add(perm);
      }
    }
    req.user.permissions = Array.from(effectivePermissions);
    return effectivePermissions;
  }

  req.user.permissions = Array.from(userPermissions);
  return userPermissions;
}

/**
 * Middleware bắt buộc người dùng phải có TẤT CẢ các quyền được chỉ định.
 */
export function requirePermission(...requiredPermissions: string[]) {
  return async (
    req: Request,
    res: Response,
    next: NextFunction,
  ): Promise<void> => {
    try {
      const userPermissions = await resolveUserPermissions(req);

      const hasAllPermissions = requiredPermissions.every((perm) =>
        userPermissions.has(perm),
      );
      if (!hasAllPermissions) {
        next(
          new AppError(
            "Forbidden: Insufficient permissions",
            403,
            ERROR_CODE.FORBIDDEN,
          ),
        );
        return;
      }

      next();
    } catch (error) {
      next(error);
    }
  };
}

/**
 * Middleware bắt buộc người dùng phải có ÍT NHẤT MỘT trong các quyền được chỉ định.
 */
export function requireAnyPermission(...requiredPermissions: string[]) {
  return async (
    req: Request,
    res: Response,
    next: NextFunction,
  ): Promise<void> => {
    try {
      const userPermissions = await resolveUserPermissions(req);

      const hasAny = requiredPermissions.some((perm) =>
        userPermissions.has(perm),
      );
      if (!hasAny) {
        next(
          new AppError(
            "Forbidden: Insufficient permissions",
            403,
            ERROR_CODE.FORBIDDEN,
          ),
        );
        return;
      }

      next();
    } catch (error) {
      next(error);
    }
  };
}
