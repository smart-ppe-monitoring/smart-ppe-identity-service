import { Router } from "express";
import { auditController } from "./audit.controller";
import {
  auditLogQuerySchema,
  auditLogIdParamSchema,
  auditLogResourceParamSchema,
  exportAuditLogSchema,
  auditSummaryQuerySchema,
  resourceAuditTrailQuerySchema,
} from "./audit.validation";
import { validate } from "../../middlewares/validate.middleware";
import { authMiddleware } from "../../middlewares/auth.middleware";
import {
  requirePermission,
  requireAnyPermission,
} from "../../middlewares/permission.middleware";
import { PERMISSIONS } from "../../common/constants/permission.constant";

const router = Router();

// 1. Lọc nhanh Audit Log thay đổi cấu hình
router.get(
  "/config-changes",
  authMiddleware,
  requirePermission(PERMISSIONS.AUDIT_LOG_READ),
  validate(auditLogQuerySchema, "query"),
  auditController.getConfigChanges,
);

// 2. Lọc nhanh Audit Log duyệt & xử lý sự cố vi phạm PPE
router.get(
  "/incident-reviews",
  authMiddleware,
  requirePermission(PERMISSIONS.AUDIT_LOG_READ),
  validate(auditLogQuerySchema, "query"),
  auditController.getIncidentReviews,
);

// 3. Thống kê KPI tổng quan hoạt động kiểm toán
router.get(
  "/summary",
  authMiddleware,
  requirePermission(PERMISSIONS.AUDIT_LOG_READ),
  validate(auditSummaryQuerySchema, "query"),
  auditController.getSummary,
);

// 4. Xuất báo cáo kiểm toán (CSV / JSON)
router.get(
  "/export",
  authMiddleware,
  requireAnyPermission(
    PERMISSIONS.AUDIT_LOG_EXPORT,
    PERMISSIONS.AUDIT_LOG_READ,
  ),
  validate(exportAuditLogSchema, "query"),
  auditController.exportLogs,
);

// 5. Lấy timeline kiểm toán của một tài nguyên cụ thể
router.get(
  "/resource/:targetType/:targetId",
  authMiddleware,
  requirePermission(PERMISSIONS.AUDIT_LOG_READ),
  validate(auditLogResourceParamSchema, "params"),
  validate(resourceAuditTrailQuerySchema, "query"),
  auditController.getResourceAuditTrail,
);

// 6. Chi tiết một bản ghi Audit Log theo ID
router.get(
  "/:id",
  authMiddleware,
  requirePermission(PERMISSIONS.AUDIT_LOG_READ),
  validate(auditLogIdParamSchema, "params"),
  auditController.getLogDetail,
);

// 7. Danh sách Audit Logs toàn hệ thống (FTS / Filter / Pagination)
router.get(
  "/",
  authMiddleware,
  requirePermission(PERMISSIONS.AUDIT_LOG_READ),
  validate(auditLogQuerySchema, "query"),
  auditController.listLogs,
);

export default router;
