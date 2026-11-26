import { openapiRegistry } from "../../config/openapi/openapi.registry";
import {
  auditLogQuerySchema,
  auditLogIdParamSchema,
  auditLogResourceParamSchema,
  exportAuditLogSchema,
  auditSummaryQuerySchema,
  resourceAuditTrailQuerySchema,
} from "./audit.validation";
import { z } from "zod";

export function registerAuditOpenApi(): void {
  openapiRegistry.register("AuditLogQuery", auditLogQuerySchema);
  openapiRegistry.register("ExportAuditLogRequest", exportAuditLogSchema);
  openapiRegistry.register("AuditLogSummaryQuery", auditSummaryQuerySchema);
  openapiRegistry.register("ResourceAuditTrailQuery", resourceAuditTrailQuerySchema);

  // 1. Danh sách Audit Logs toàn hệ thống
  openapiRegistry.registerPath({
    method: "get",
    path: "/audit-logs",
    tags: ["Audit Logs"],
    summary: "Tra cứu danh sách nhật ký kiểm toán Identity Service",
    description:
      "Phạm vi Database-per-Service: lưu trữ nhật ký thuộc Identity, Auth, RBAC, Maintenance, Cron, Integration và System Config (`ppe_identity_db`). Hỗ trợ phân trang, lọc theo danh mục, trạng thái (`SUCCESS` | `FAILED`), người thực hiện, hành động, tài nguyên, khoảng thời gian và Full-Text Search.",
    security: [{ BearerAuth: [] }],
    request: { query: auditLogQuerySchema },
    responses: {
      200: {
        description: "Lấy danh sách nhật ký kiểm toán thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean(),
              data: z.array(z.record(z.unknown())),
              meta: z.object({
                page: z.number(),
                limit: z.number(),
                total: z.number(),
                totalPages: z.number(),
                hasNextPage: z.boolean(),
                hasPrevPage: z.boolean(),
              }),
            }),
          },
        },
      },
    },
  });

  // 2. Lọc nhanh thay đổi cấu hình
  openapiRegistry.registerPath({
    method: "get",
    path: "/audit-logs/config-changes",
    tags: ["Audit Logs"],
    summary: "Lọc nhanh nhật ký thay đổi cấu hình hệ thống & Feature Flags",
    description:
      "Lọc các thao tác thay đổi cấu hình hệ thống (`SYSTEM_CONFIG`, `FEATURE_FLAG`, v.v.) trong phạm vi `smart-ppe-identity-service`. Hỗ trợ lọc `status` (`SUCCESS` | `FAILED`), khoảng thời gian và Full-Text Search.",
    security: [{ BearerAuth: [] }],
    request: { query: auditLogQuerySchema },
    responses: {
      200: {
        description: "Lấy danh sách thay đổi cấu hình thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean(),
              data: z.array(z.record(z.unknown())),
              meta: z.record(z.unknown()),
            }),
          },
        },
      },
    },
  });

  // 3. Lọc nhanh duyệt & xử lý sự cố vi phạm (DEPRECATED)
  openapiRegistry.registerPath({
    method: "get",
    path: "/audit-logs/incident-reviews",
    tags: ["Audit Logs"],
    deprecated: true,
    summary: "[DEPRECATED] Lọc nhanh nhật ký duyệt sự cố vi phạm PPE",
    description:
      "DEPRECATED: Theo ranh giới Database-per-Service, `smart-ppe-identity-service` chỉ lưu trữ audit log thuộc Identity, RBAC, Auth và System Config. Nhật ký xử lý sự cố PPE thuộc phạm vi `smart-ppe-incident-service`. Endpoint giữ lại để tương thích ngược và trả kèm header `Deprecation: true`.",
    security: [{ BearerAuth: [] }],
    request: { query: auditLogQuerySchema },
    responses: {
      200: {
        description: "Lấy danh sách duyệt sự cố thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean(),
              data: z.array(z.record(z.unknown())),
              meta: z.record(z.unknown()),
            }),
          },
        },
      },
    },
  });

  // 4. Thống kê KPI tổng quan
  openapiRegistry.registerPath({
    method: "get",
    path: "/audit-logs/summary",
    tags: ["Audit Logs"],
    summary: "Thống kê KPI tổng quan hoạt động kiểm toán (Identity Scope)",
    description:
      "Trả về `scope: \"IDENTITY\"`, tổng số logs, `successCount`, `failedCount`, `successRate`, thống kê theo danh mục (`categoryCounts.incidentReview` được giữ lại để tương thích ngược và đánh dấu deprecated do ranh giới Database-per-Service), top actors và top actions.",
    security: [{ BearerAuth: [] }],
    request: { query: auditSummaryQuerySchema },
    responses: {
      200: {
        description: "Lấy thống kê thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean(),
              data: z.record(z.unknown()),
            }),
          },
        },
      },
    },
  });

  // 5. Xuất báo cáo kiểm toán (CSV / JSON)
  openapiRegistry.registerPath({
    method: "get",
    path: "/audit-logs/export",
    tags: ["Audit Logs"],
    summary: "Xuất file báo cáo nhật ký kiểm toán (CSV / JSON)",
    description:
      "Xuất dữ liệu kiểm toán phục vụ biên bản pháp lý, thanh tra an toàn và lưu trữ chống chối bỏ. Hỗ trợ lọc `status` (`SUCCESS` | `FAILED`) và validate định dạng ngày cũng như ràng buộc `endDate >= startDate`.",
    security: [{ BearerAuth: [] }],
    request: { query: exportAuditLogSchema },
    responses: {
      200: {
        description: "Xuất dữ liệu kiểm toán thành công",
        content: {
          "text/csv": {
            schema: z.string(),
          },
          "application/json": {
            schema: z.object({
              success: z.boolean(),
              data: z.array(z.record(z.unknown())),
              count: z.number(),
            }),
          },
        },
      },
    },
  });

  // 6. Lấy timeline lịch sử của một tài nguyên
  openapiRegistry.registerPath({
    method: "get",
    path: "/audit-logs/resource/{targetType}/{targetId}",
    tags: ["Audit Logs"],
    summary: "Lấy toàn bộ timeline lịch sử kiểm toán của một tài nguyên cụ thể",
    description:
      "Xem toàn bộ lịch sử thay đổi và trạng thái (`SUCCESS` | `FAILED`) của một tài nguyên thuộc phạm vi Identity Service (`USER`, `ROLE`, `SYSTEM_CONFIG`, `CRON_JOB`, `API_KEY`, `WEBHOOK_ENDPOINT`, ...).",
    security: [{ BearerAuth: [] }],
    request: {
      params: auditLogResourceParamSchema,
      query: resourceAuditTrailQuerySchema,
    },
    responses: {
      200: {
        description: "Lấy timeline tài nguyên thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean(),
              data: z.array(z.record(z.unknown())),
            }),
          },
        },
      },
    },
  });

  // 7. Chi tiết 1 bản ghi Audit Log
  openapiRegistry.registerPath({
    method: "get",
    path: "/audit-logs/{id}",
    tags: ["Audit Logs"],
    summary: "Xem chi tiết một bản ghi nhật ký kiểm toán",
    security: [{ BearerAuth: [] }],
    request: {
      params: auditLogIdParamSchema,
    },
    responses: {
      200: {
        description: "Lấy chi tiết bản ghi thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean(),
              data: z.record(z.unknown()),
            }),
          },
        },
      },
    },
  });
}
