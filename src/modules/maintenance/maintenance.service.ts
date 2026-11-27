import {
  maintenanceRepository,
  MaintenanceRepository,
} from "./maintenance.repository";
import {
  maintenanceCacheService,
  MaintenanceCacheService,
} from "../../common/services/maintenance-cache.service";
import { sseManagerService } from "../../common/services/sse-manager.service";
import {
  EnableMaintenanceDto,
  UpdateMaintenanceDto,
  PublicMaintenanceStatusDto,
} from "./maintenance.dto";
import {
  AUDIT_ACTION,
  AUDIT_TARGET_TYPE,
} from "../../common/constants/audit-log.constant";
import {
  MAINTENANCE_STATUS,
  MaintenanceStatus,
} from "../../common/constants/maintenance.constant";
import { ROLES } from "../../common/constants/role.constant";
import { PERMISSIONS } from "../../common/constants/permission.constant";
import { AppError } from "../../common/errors/app-error";
import { ERROR_CODE } from "../../common/errors/error-code";
import { isValidIpOrCidr } from "../../common/helpers/ip.helper";

export class MaintenanceService {
  constructor(
    private repo: MaintenanceRepository = maintenanceRepository,
    private cacheService: MaintenanceCacheService = maintenanceCacheService,
  ) {}

  private normalizeStringArray(value: unknown): string[] {
    if (!Array.isArray(value)) return [];
    return value
      .filter((item): item is string => typeof item === "string")
      .map((item) => item.trim())
      .filter((item) => item.length > 0);
  }

  private assertValidBypassIps(bypassIps: string[]): void {
    for (const ip of bypassIps) {
      if (!isValidIpOrCidr(ip)) {
        throw new AppError(
          `Địa chỉ IP/CIDR miễn trừ không hợp lệ: '${ip}'`,
          400,
          ERROR_CODE.VALIDATION_ERROR,
        );
      }
    }
  }

  private assertAdminAntiLockout(
    bypassRoles: string[],
    bypassPermissions: string[],
  ): void {
    const hasAdminRole = bypassRoles.includes(ROLES.ADMIN);
    const hasManagePerm = bypassPermissions.includes(
      PERMISSIONS.MAINTENANCE_MANAGE,
    );
    if (!hasAdminRole && !hasManagePerm) {
      throw new AppError(
        `Không thể gỡ bỏ hoàn toàn quyền truy cập quản trị khi bảo trì: cần giữ lại ít nhất vai trò ${ROLES.ADMIN} trong bypassRoles hoặc quyền ${PERMISSIONS.MAINTENANCE_MANAGE} trong bypassPermissions`,
        400,
        ERROR_CODE.VALIDATION_ERROR,
      );
    }
  }

  async getConfig(key = "DEFAULT") {
    const config = await this.repo.getOrCreateDefaultConfig(key);
    return config;
  }

  async getPublicStatus(key = "DEFAULT"): Promise<PublicMaintenanceStatusDto> {
    const config = await this.cacheService.getConfig(key);
    return {
      enabled: config.enabled,
      status: config.status as MaintenanceStatus,
      title: config.title,
      message: config.message,
      startAt: config.startAt ? config.startAt.toISOString() : null,
      estimatedEndAt: config.estimatedEndAt
        ? config.estimatedEndAt.toISOString()
        : null,
    };
  }

  async enableMaintenance(
    dto: EnableMaintenanceDto,
    context?: { actorId?: string; ipAddress?: string; userAgent?: string },
  ) {
    const previousConfig = await this.repo.getOrCreateDefaultConfig();

    const startAt =
      dto.startAt !== undefined
        ? dto.startAt
          ? new Date(dto.startAt)
          : null
        : new Date();
    const referenceMs = startAt ? startAt.getTime() : Date.now();
    const previousEstimatedEndAt = previousConfig.estimatedEndAt
      ? new Date(previousConfig.estimatedEndAt)
      : null;
    const inheritedEstimatedEndAt =
      previousEstimatedEndAt && previousEstimatedEndAt.getTime() > referenceMs
        ? previousEstimatedEndAt
        : null;

    const estimatedEndAt =
      dto.estimatedEndAt !== undefined
        ? dto.estimatedEndAt
          ? new Date(dto.estimatedEndAt)
          : null
        : inheritedEstimatedEndAt;

    if (
      dto.estimatedEndAt !== undefined &&
      startAt &&
      estimatedEndAt &&
      estimatedEndAt.getTime() <= startAt.getTime()
    ) {
      throw new AppError(
        "estimatedEndAt must be after startAt",
        400,
        ERROR_CODE.VALIDATION_ERROR,
      );
    }

    const nextBypassPermissions = this.normalizeStringArray(
      dto.bypassPermissions !== undefined
        ? dto.bypassPermissions
        : previousConfig.bypassPermissions,
    );
    const nextBypassRoles = this.normalizeStringArray(
      dto.bypassRoles !== undefined
        ? dto.bypassRoles
        : previousConfig.bypassRoles,
    );
    this.assertAdminAntiLockout(nextBypassRoles, nextBypassPermissions);

    const nextBypassIps = this.normalizeStringArray(
      dto.bypassIps !== undefined ? dto.bypassIps : previousConfig.bypassIps,
    );
    if (dto.bypassIps !== undefined) {
      this.assertValidBypassIps(nextBypassIps);
    }

    const newStatus = dto.status || MAINTENANCE_STATUS.MAINTENANCE;

    const updatedConfig = await this.repo.updateConfig(previousConfig.key, {
      enabled: true,
      status: newStatus,
      title: dto.title ?? previousConfig.title,
      message: dto.message ?? previousConfig.message,
      startAt,
      estimatedEndAt,
      bypassPermissions: nextBypassPermissions as any,
      bypassRoles: nextBypassRoles as any,
      bypassIps: nextBypassIps as any,
    });

    this.cacheService.invalidate();

    // Broadcast SSE event
    sseManagerService.broadcast({
      type: "system:maintenance",
      data: {
        enabled: updatedConfig.enabled,
        status: updatedConfig.status,
        title: updatedConfig.title,
        message: updatedConfig.message,
        startAt: updatedConfig.startAt
          ? updatedConfig.startAt.toISOString()
          : null,
        estimatedEndAt: updatedConfig.estimatedEndAt
          ? updatedConfig.estimatedEndAt.toISOString()
          : null,
      },
    });

    // Audit log
    await this.repo.createAuditLog({
      actorId: context?.actorId,
      action: AUDIT_ACTION.ENABLE_MAINTENANCE,
      targetType: AUDIT_TARGET_TYPE.MAINTENANCE_CONFIG,
      targetId: updatedConfig.id,
      details: {
        previous: {
          enabled: previousConfig.enabled,
          status: previousConfig.status,
          title: previousConfig.title,
          estimatedEndAt: previousConfig.estimatedEndAt,
        },
        current: {
          enabled: updatedConfig.enabled,
          status: updatedConfig.status,
          title: updatedConfig.title,
          estimatedEndAt: updatedConfig.estimatedEndAt,
        },
      },
      ipAddress: context?.ipAddress,
      userAgent: context?.userAgent,
    });

    return updatedConfig;
  }

  async updateConfig(
    dto: UpdateMaintenanceDto,
    context?: { actorId?: string; ipAddress?: string; userAgent?: string },
  ) {
    const previousConfig = await this.repo.getOrCreateDefaultConfig();

    let enabled =
      dto.enabled !== undefined ? dto.enabled : previousConfig.enabled;
    let status = dto.status !== undefined ? dto.status : previousConfig.status;

    if (dto.status === MAINTENANCE_STATUS.ONLINE) {
      enabled = false;
    } else if (
      dto.status === MAINTENANCE_STATUS.MAINTENANCE ||
      dto.status === MAINTENANCE_STATUS.READ_ONLY
    ) {
      enabled = true;
    } else if (dto.enabled !== undefined) {
      status = dto.enabled
        ? MAINTENANCE_STATUS.MAINTENANCE
        : MAINTENANCE_STATUS.ONLINE;
    }

    const isTurningOff = Boolean(previousConfig.enabled) && !enabled;

    const startAt =
      dto.startAt !== undefined
        ? dto.startAt
          ? new Date(dto.startAt)
          : null
        : isTurningOff
          ? null
          : previousConfig.startAt;
    const estimatedEndAt =
      dto.estimatedEndAt !== undefined
        ? dto.estimatedEndAt
          ? new Date(dto.estimatedEndAt)
          : null
        : isTurningOff
          ? null
          : previousConfig.estimatedEndAt;

    if (
      (dto.startAt !== undefined || dto.estimatedEndAt !== undefined) &&
      startAt &&
      estimatedEndAt &&
      estimatedEndAt.getTime() <= startAt.getTime()
    ) {
      throw new AppError(
        "estimatedEndAt must be after startAt",
        400,
        ERROR_CODE.VALIDATION_ERROR,
      );
    }

    const nextBypassPermissions = this.normalizeStringArray(
      dto.bypassPermissions !== undefined
        ? dto.bypassPermissions
        : previousConfig.bypassPermissions,
    );
    const nextBypassRoles = this.normalizeStringArray(
      dto.bypassRoles !== undefined
        ? dto.bypassRoles
        : previousConfig.bypassRoles,
    );
    this.assertAdminAntiLockout(nextBypassRoles, nextBypassPermissions);

    const nextBypassIps = this.normalizeStringArray(
      dto.bypassIps !== undefined ? dto.bypassIps : previousConfig.bypassIps,
    );
    if (dto.bypassIps !== undefined) {
      this.assertValidBypassIps(nextBypassIps);
    }

    const updatedConfig = await this.repo.updateConfig(previousConfig.key, {
      enabled,
      status,
      title: dto.title ?? previousConfig.title,
      message: dto.message ?? previousConfig.message,
      startAt,
      estimatedEndAt,
      bypassPermissions: nextBypassPermissions as any,
      bypassRoles: nextBypassRoles as any,
      bypassIps: nextBypassIps as any,
    });

    this.cacheService.invalidate();

    // Broadcast SSE event
    sseManagerService.broadcast({
      type: "system:maintenance",
      data: {
        enabled: updatedConfig.enabled,
        status: updatedConfig.status,
        title: updatedConfig.title,
        message: updatedConfig.message,
        startAt: updatedConfig.startAt
          ? updatedConfig.startAt.toISOString()
          : null,
        estimatedEndAt: updatedConfig.estimatedEndAt
          ? updatedConfig.estimatedEndAt.toISOString()
          : null,
      },
    });

    // Audit log
    await this.repo.createAuditLog({
      actorId: context?.actorId,
      action: AUDIT_ACTION.UPDATE_MAINTENANCE,
      targetType: AUDIT_TARGET_TYPE.MAINTENANCE_CONFIG,
      targetId: updatedConfig.id,
      details: {
        previous: {
          enabled: previousConfig.enabled,
          status: previousConfig.status,
          title: previousConfig.title,
          estimatedEndAt: previousConfig.estimatedEndAt,
        },
        current: {
          enabled: updatedConfig.enabled,
          status: updatedConfig.status,
          title: updatedConfig.title,
          estimatedEndAt: updatedConfig.estimatedEndAt,
        },
      },
      ipAddress: context?.ipAddress,
      userAgent: context?.userAgent,
    });

    return updatedConfig;
  }

  async disableMaintenance(context?: {
    actorId?: string;
    ipAddress?: string;
    userAgent?: string;
  }) {
    const previousConfig = await this.repo.getOrCreateDefaultConfig();

    const updatedConfig = await this.repo.updateConfig(previousConfig.key, {
      enabled: false,
      status: MAINTENANCE_STATUS.ONLINE,
      startAt: null,
      estimatedEndAt: null,
    });

    this.cacheService.invalidate();

    // Broadcast SSE event nhất quán với trạng thái đã lưu trong CSDL
    sseManagerService.broadcast({
      type: "system:maintenance",
      data: {
        enabled: updatedConfig.enabled,
        status: updatedConfig.status,
        title: updatedConfig.title,
        message: updatedConfig.message,
        startAt: updatedConfig.startAt
          ? updatedConfig.startAt.toISOString()
          : null,
        estimatedEndAt: updatedConfig.estimatedEndAt
          ? updatedConfig.estimatedEndAt.toISOString()
          : null,
      },
    });

    // Audit log
    await this.repo.createAuditLog({
      actorId: context?.actorId,
      action: AUDIT_ACTION.DISABLE_MAINTENANCE,
      targetType: AUDIT_TARGET_TYPE.MAINTENANCE_CONFIG,
      targetId: updatedConfig.id,
      details: {
        previous: {
          enabled: previousConfig.enabled,
          status: previousConfig.status,
          startAt: previousConfig.startAt,
          estimatedEndAt: previousConfig.estimatedEndAt,
        },
        current: {
          enabled: updatedConfig.enabled,
          status: updatedConfig.status,
          startAt: updatedConfig.startAt,
          estimatedEndAt: updatedConfig.estimatedEndAt,
        },
      },
      ipAddress: context?.ipAddress,
      userAgent: context?.userAgent,
    });

    return updatedConfig;
  }
}

export const maintenanceService = new MaintenanceService();
