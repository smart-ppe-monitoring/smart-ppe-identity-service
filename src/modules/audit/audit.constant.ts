import {
  AUDIT_ACTION,
  AUDIT_TARGET_TYPE,
  AuditAction,
  AuditTargetType,
  SYSTEM_TARGET_ID,
} from "../../common/constants/audit-log.constant";

export {
  AUDIT_ACTION,
  AUDIT_TARGET_TYPE,
  AuditAction,
  AuditTargetType,
  SYSTEM_TARGET_ID,
};

/**
 * Phân loại danh mục Audit Log phục vụ lọc nhanh theo nghiệp vụ
 */
export const AUDIT_CATEGORY = {
  ALL: "ALL",
  CONFIG: "CONFIG",
  /**
   * @deprecated Thuộc phạm vi `smart-ppe-incident-service` theo nguyên lý Database-per-Service.
   * Giữ lại để tương thích ngược; `smart-ppe-identity-service` chỉ lưu trữ audit log Identity/RBAC/Auth/System Config.
   */
  INCIDENT_REVIEW: "INCIDENT_REVIEW",
  ACCESS_CONTROL: "ACCESS_CONTROL",
  SYSTEM: "SYSTEM",
} as const;

export type AuditCategory =
  (typeof AUDIT_CATEGORY)[keyof typeof AUDIT_CATEGORY];

/**
 * Trạng thái kết quả của bản ghi Audit Log
 */
export const AUDIT_LOG_STATUS = {
  SUCCESS: "SUCCESS",
  FAILED: "FAILED",
} as const;

export type AuditLogStatus =
  (typeof AUDIT_LOG_STATUS)[keyof typeof AUDIT_LOG_STATUS];

/**
 * Phạm vi sở hữu dữ liệu Audit Log của microservice (Database-per-Service)
 */
export const AUDIT_SCOPE = {
  IDENTITY: "IDENTITY",
} as const;

export type AuditScope = (typeof AUDIT_SCOPE)[keyof typeof AUDIT_SCOPE];

export const AUDIT_FAILED_ACTION_REGEX = /(^|_)(FAIL|FAILED|ERROR|DENIED|REJECTED)$/i;

export const AUDIT_FAILED_DETAIL_STATUSES = ["FAILED", "ERROR"] as const;

export const AUDIT_DEPRECATION_NOTICE =
  "Deprecated: smart-ppe-identity-service only stores Identity, RBAC, Auth, and System Config audit logs. Incident review audit logs belong to smart-ppe-incident-service under Database-per-Service isolation.";

/**
 * Suy diễn trạng thái SUCCESS | FAILED từ action và payload details của bản ghi Audit Log.
 * Đồng bộ hoàn toàn với predicate SQL ở AuditRepository và logic chuẩn hóa ở Frontend.
 */
export function deriveAuditLogStatus(
  action: string,
  details?: Record<string, unknown> | null,
): AuditLogStatus {
  const isPlainDetails =
    Boolean(details) && typeof details === "object" && !Array.isArray(details);

  if (isPlainDetails && details) {
    if (
      typeof details.status === "string" &&
      (AUDIT_FAILED_DETAIL_STATUSES as readonly string[]).includes(
        details.status.trim().toUpperCase(),
      )
    ) {
      return AUDIT_LOG_STATUS.FAILED;
    }

    if (details.success === false) {
      return AUDIT_LOG_STATUS.FAILED;
    }

    if (
      typeof details.errorMessage === "string" &&
      details.errorMessage.trim().length > 0
    ) {
      return AUDIT_LOG_STATUS.FAILED;
    }

    if (
      details.error !== undefined &&
      details.error !== null &&
      details.error !== false &&
      (typeof details.error !== "string" || details.error.trim().length > 0)
    ) {
      return AUDIT_LOG_STATUS.FAILED;
    }
  }

  if (
    action === AUDIT_ACTION.ACCOUNT_LOCKED ||
    AUDIT_FAILED_ACTION_REGEX.test(action)
  ) {
    return AUDIT_LOG_STATUS.FAILED;
  }

  return AUDIT_LOG_STATUS.SUCCESS;
}

/**
 * Danh sách Audit Action tương ứng với từng Category
 */
export const AUDIT_CATEGORY_ACTIONS: Record<
  Exclude<AuditCategory, "ALL">,
  readonly AuditAction[]
> = {
  CONFIG: [
    AUDIT_ACTION.UPDATE_PPE_SAFETY_CONFIG,
    AUDIT_ACTION.UPDATE_PPE_CAMERA_SAFETY_CONFIG,
    AUDIT_ACTION.DELETE_PPE_CAMERA_SAFETY_CONFIG,
    AUDIT_ACTION.CREATE_PPE_SITE,
    AUDIT_ACTION.UPDATE_PPE_SITE,
    AUDIT_ACTION.DELETE_PPE_SITE,
    AUDIT_ACTION.REGISTER_PPE_CAMERA,
    AUDIT_ACTION.UPDATE_PPE_CAMERA,
    AUDIT_ACTION.DELETE_PPE_CAMERA,
    AUDIT_ACTION.CREATE_SYSTEM_CONFIG,
    AUDIT_ACTION.UPDATE_SYSTEM_CONFIG,
    AUDIT_ACTION.DELETE_SYSTEM_CONFIG,
    AUDIT_ACTION.TOGGLE_FEATURE_FLAG,
  ],
  /**
   * @deprecated Incident review actions belong to `smart-ppe-incident-service` (Database-per-Service).
   */
  INCIDENT_REVIEW: [
    AUDIT_ACTION.CREATE_PPE_INCIDENT,
    AUDIT_ACTION.REVIEW_PPE_INCIDENT,
    AUDIT_ACTION.UPDATE_PPE_INCIDENT,
    AUDIT_ACTION.RESOLVE_PPE_INCIDENT,
    AUDIT_ACTION.CLOSE_PPE_INCIDENT,
    AUDIT_ACTION.DELETE_PPE_INCIDENT,
    AUDIT_ACTION.ASSIGN_PPE_INCIDENT,
    AUDIT_ACTION.COMMENT_PPE_INCIDENT,
  ],
  ACCESS_CONTROL: [
    AUDIT_ACTION.CREATE_ROLE,
    AUDIT_ACTION.UPDATE_ROLE,
    AUDIT_ACTION.DELETE_ROLE,
    AUDIT_ACTION.SYNC_ROLE_PERMISSIONS,
    AUDIT_ACTION.REMOVE_ROLE_PERMISSION,
    AUDIT_ACTION.ASSIGN_USER_ROLE,
    AUDIT_ACTION.ENABLE_2FA,
    AUDIT_ACTION.DISABLE_2FA,
    AUDIT_ACTION.REVOKE_USER_SESSION,
    AUDIT_ACTION.REVOKE_ALL_USER_SESSIONS,
    AUDIT_ACTION.DELETE_USER,
    AUDIT_ACTION.RESTORE_USER,
    AUDIT_ACTION.ADMIN_RESET_PASSWORD,
  ],
  SYSTEM: [
    AUDIT_ACTION.ENABLE_MAINTENANCE,
    AUDIT_ACTION.UPDATE_MAINTENANCE,
    AUDIT_ACTION.DISABLE_MAINTENANCE,
    AUDIT_ACTION.TRIGGER_CRON_JOB,
    AUDIT_ACTION.TOGGLE_CRON_JOB,
    AUDIT_ACTION.CLEANUP_AUDIT_LOGS,
    AUDIT_ACTION.GENERATE_PPE_REPORT,
    AUDIT_ACTION.AGGREGATE_DAILY_STATISTICS,
    AUDIT_ACTION.DEPLOY_AI_MODEL_VERSION,
  ],
};

export const AUDIT_EXPORT_FORMAT = {
  JSON: "json",
  CSV: "csv",
} as const;

export type AuditExportFormat =
  (typeof AUDIT_EXPORT_FORMAT)[keyof typeof AUDIT_EXPORT_FORMAT];
