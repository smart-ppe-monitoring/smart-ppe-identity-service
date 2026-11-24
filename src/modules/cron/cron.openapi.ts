import { openapiRegistry } from "../../config/openapi/openapi.registry";
import {
  cronJobNameParamSchema,
  triggerCronJobSchema,
  listCronJobsQuerySchema,
  updateCronJobSchema,
} from "./cron.validation";
import { z } from "zod";

export function registerCronOpenApi(): void {
  openapiRegistry.register("TriggerCronJobRequest", triggerCronJobSchema);
  openapiRegistry.register("UpdateCronJobRequest", updateCronJobSchema);

  const cronJobItemSchema = z.object({
    name: z.string().openapi({ example: "cleanup-audit-logs" }),
    cron: z.string().openapi({ example: "0 2 * * *" }),
    schedule: z.object({
      frequency: z.enum(["HOURLY", "DAILY", "WEEKLY", "MONTHLY"]),
      everyHours: z.number().optional(),
      dayOfWeek: z.number().optional(),
      dayOfMonth: z.number().optional(),
      hour: z.number().optional(),
      minute: z.number(),
    }),
    scheduleLabel: z
      .string()
      .openapi({ example: "02:00 hàng ngày (UTC+7)" }),
    description: z.string().openapi({
      example: "Dọn dẹp các bản ghi Audit Logs cũ hơn 30 ngày",
    }),
    isEnabled: z.boolean().openapi({
      example: true,
      description: "Trạng thái bật/tắt lịch trình tự động của job",
    }),
    defaultParams: z.object({
      retentionDays: z.number().optional(),
      maxAgeHours: z.number().optional(),
    }),
    lastStatus: z.string().openapi({ example: "READY" }),
  });

  // GET /cron/jobs
  openapiRegistry.registerPath({
    method: "get",
    path: "/cron/jobs",
    tags: ["Scheduled Tasks & Cron Jobs"],
    summary:
      "Danh sách toàn bộ các tác vụ nền định kỳ (Cron Jobs) trong hệ thống",
    security: [{ BearerAuth: [] }],
    request: { query: listCronJobsQuerySchema },
    responses: {
      200: {
        description: "Lấy danh sách tác vụ thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean().openapi({ example: true }),
              data: z.array(cronJobItemSchema),
            }),
          },
        },
      },
      403: { description: "Không có quyền CRON_JOB_READ" },
    },
  });

  // POST /cron/jobs/:jobName/trigger
  openapiRegistry.registerPath({
    method: "post",
    path: "/cron/jobs/{jobName}/trigger",
    tags: ["Scheduled Tasks & Cron Jobs"],
    summary:
      "Kích hoạt chạy ngay một Cron Job bất kỳ (Manual Trigger từ Admin)",
    security: [{ BearerAuth: [] }],
    request: {
      params: cronJobNameParamSchema,
      body: {
        content: { "application/json": { schema: triggerCronJobSchema } },
      },
    },
    responses: {
      200: {
        description: "Tác vụ đã được thực thi thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean().openapi({ example: true }),
              message: z.string().openapi({
                example:
                  "Tác vụ 'cleanup-audit-logs' đã được kích hoạt và thực thi thành công",
              }),
              data: z.object({
                jobName: z.string().openapi({ example: "cleanup-audit-logs" }),
                success: z.boolean().openapi({ example: true }),
                durationMs: z.number().openapi({ example: 45 }),
                data: z.record(z.unknown()),
              }),
            }),
          },
        },
      },
      400: {
        description: "Tên job không hợp lệ hoặc tham số không đúng định dạng",
      },
      403: { description: "Không có quyền CRON_JOB_MANAGE" },
    },
  });

  // PATCH /cron/jobs/:jobName/toggle
  openapiRegistry.registerPath({
    method: "patch",
    path: "/cron/jobs/{jobName}/toggle",
    tags: ["Scheduled Tasks & Cron Jobs"],
    summary: "Bật / Tắt lịch trình tự động của một Cron Job",
    description:
      "Toggle trạng thái `isEnabled` của job. Khi tắt, lịch trình BullMQ bị xóa; khi bật lại, lịch trình được đăng ký lại. Trạng thái lưu in-memory và reset về `enabled` khi server khởi động lại.",
    security: [{ BearerAuth: [] }],
    request: { params: cronJobNameParamSchema },
    responses: {
      200: {
        description: "Toggle trạng thái thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean().openapi({ example: true }),
              message: z.string().openapi({
                example: "Tác vụ 'cleanup-audit-logs' đã được tắt thành công",
              }),
              data: z.object({
                jobName: z.string().openapi({ example: "cleanup-audit-logs" }),
                isEnabled: z.boolean().openapi({
                  example: false,
                  description: "Trạng thái mới sau khi toggle",
                }),
              }),
            }),
          },
        },
      },
      400: { description: "Tên job không hợp lệ" },
      403: { description: "Không có quyền CRON_JOB_MANAGE" },
    },
  });

  // PATCH /cron/jobs/:jobName
  openapiRegistry.registerPath({
    method: "patch",
    path: "/cron/jobs/{jobName}",
    tags: ["Scheduled Tasks & Cron Jobs"],
    summary: "Cập nhật lịch chạy trực quan, mô tả và tham số mặc định của Cron Job",
    security: [{ BearerAuth: [] }],
    request: {
      params: cronJobNameParamSchema,
      body: {
        content: { "application/json": { schema: updateCronJobSchema } },
      },
    },
    responses: {
      200: {
        description: "Cập nhật cấu hình tác vụ thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean().openapi({ example: true }),
              message: z.string(),
              data: cronJobItemSchema,
            }),
          },
        },
      },
      400: { description: "Tham số lịch chạy không hợp lệ" },
      403: { description: "Không có quyền CRON_JOB_MANAGE" },
    },
  });

  // PUT /cron/jobs/:jobName
  openapiRegistry.registerPath({
    method: "put",
    path: "/cron/jobs/{jobName}",
    tags: ["Scheduled Tasks & Cron Jobs"],
    summary: "Cập nhật lịch chạy trực quan, mô tả và tham số mặc định của Cron Job (PUT alias)",
    security: [{ BearerAuth: [] }],
    request: {
      params: cronJobNameParamSchema,
      body: {
        content: { "application/json": { schema: updateCronJobSchema } },
      },
    },
    responses: {
      200: {
        description: "Cập nhật cấu hình tác vụ thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean().openapi({ example: true }),
              message: z.string(),
              data: cronJobItemSchema,
            }),
          },
        },
      },
      400: { description: "Tham số lịch chạy không hợp lệ" },
      403: { description: "Không có quyền CRON_JOB_MANAGE" },
    },
  });
}
