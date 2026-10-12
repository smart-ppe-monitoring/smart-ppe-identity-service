import { z } from "zod";
import { uuidSchema } from "../../common/validations/common.validation";
import { AUDIT_CATEGORY, AUDIT_EXPORT_FORMAT } from "./audit.constant";
import {
  VIETNAM_DATE_REGEX,
  ISO_DATE_REGEX,
} from "../../common/constants/date.constant";

export const auditLogQuerySchema = z
  .object({
    category: z.nativeEnum(AUDIT_CATEGORY).optional(),
    actorId: uuidSchema.optional(),
    action: z.string().trim().max(100).optional(),
    targetType: z.string().trim().max(100).optional(),
    targetId: z.string().trim().max(100).optional(),
    search: z
      .string()
      .trim()
      .max(100, "Từ khóa tìm kiếm tối đa 100 ký tự")
      .optional(),
    startDate: z
      .string()
      .max(50, "startDate tối đa 50 ký tự")
      .refine(
        (val) =>
          !val ||
          VIETNAM_DATE_REGEX.test(val) ||
          ISO_DATE_REGEX.test(val) ||
          !isNaN(Date.parse(val)),
        {
          message:
            "startDate phải là định dạng DD/MM/YYYY, YYYY-MM-DD hoặc ISO 8601 hợp lệ",
        },
      )
      .optional(),
    endDate: z
      .string()
      .max(50, "endDate tối đa 50 ký tự")
      .refine(
        (val) =>
          !val ||
          VIETNAM_DATE_REGEX.test(val) ||
          ISO_DATE_REGEX.test(val) ||
          !isNaN(Date.parse(val)),
        {
          message:
            "endDate phải là định dạng DD/MM/YYYY, YYYY-MM-DD hoặc ISO 8601 hợp lệ",
        },
      )
      .optional(),
    page: z.coerce.number().int().positive().default(1),
    limit: z.coerce.number().int().positive().max(100).default(20),
    sortBy: z
      .enum(["createdAt", "action", "targetType"])
      .default("createdAt"),
    order: z.enum(["asc", "desc"]).default("desc"),
  })
  .refine(
    (data) => {
      if (data.startDate && data.endDate) {
        const start = new Date(data.startDate);
        const end = new Date(data.endDate);
        if (!isNaN(start.getTime()) && !isNaN(end.getTime())) {
          return end >= start;
        }
      }
      return true;
    },
    {
      message: "endDate phải lớn hơn hoặc bằng startDate",
      path: ["endDate"],
    },
  );

export const auditLogIdParamSchema = z.object({
  id: uuidSchema,
});

export const auditLogResourceParamSchema = z.object({
  targetType: z.string().trim().min(1, "targetType không được để trống").max(100),
  targetId: z.string().trim().min(1, "targetId không được để trống").max(100),
});

export const exportAuditLogSchema = z.object({
  format: z.nativeEnum(AUDIT_EXPORT_FORMAT).default("csv"),
  category: z.nativeEnum(AUDIT_CATEGORY).optional(),
  actorId: uuidSchema.optional(),
  action: z.string().trim().max(100).optional(),
  targetType: z.string().trim().max(100).optional(),
  targetId: z.string().trim().max(100).optional(),
  search: z.string().trim().max(100).optional(),
  startDate: z.string().max(50).optional(),
  endDate: z.string().max(50).optional(),
});

export const auditSummaryQuerySchema = z
  .object({
    startDate: z
      .string()
      .max(50, "startDate tối đa 50 ký tự")
      .refine(
        (val) =>
          !val ||
          VIETNAM_DATE_REGEX.test(val) ||
          ISO_DATE_REGEX.test(val) ||
          !isNaN(Date.parse(val)),
        {
          message:
            "startDate phải là định dạng DD/MM/YYYY, YYYY-MM-DD hoặc ISO 8601 hợp lệ",
        },
      )
      .optional(),
    endDate: z
      .string()
      .max(50, "endDate tối đa 50 ký tự")
      .refine(
        (val) =>
          !val ||
          VIETNAM_DATE_REGEX.test(val) ||
          ISO_DATE_REGEX.test(val) ||
          !isNaN(Date.parse(val)),
        {
          message:
            "endDate phải là định dạng DD/MM/YYYY, YYYY-MM-DD hoặc ISO 8601 hợp lệ",
        },
      )
      .optional(),
  })
  .refine(
    (data) => {
      if (data.startDate && data.endDate) {
        const start = new Date(data.startDate);
        const end = new Date(data.endDate);
        if (!isNaN(start.getTime()) && !isNaN(end.getTime())) {
          return end >= start;
        }
      }
      return true;
    },
    {
      message: "endDate phải lớn hơn hoặc bằng startDate",
      path: ["endDate"],
    },
  );

export const resourceAuditTrailQuerySchema = z.object({
  limit: z.coerce.number().int().positive().max(200).default(50).optional(),
});

