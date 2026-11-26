import { z } from "zod";
import { uuidSchema } from "../../common/validations/common.validation";
import {
  AUDIT_CATEGORY,
  AUDIT_EXPORT_FORMAT,
  AUDIT_LOG_STATUS,
} from "./audit.constant";
import {
  VIETNAM_DATE_REGEX,
  ISO_DATE_REGEX,
} from "../../common/constants/date.constant";
import { getVietnamDayRange } from "../../common/helpers/date.helper";

const ISO_DATETIME_REGEX =
  /^(\d{4}-\d{2}-\d{2})T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:\d{2})?$/;

function isValidAuditDate(val: string): boolean {
  if (!val) return true;

  if (VIETNAM_DATE_REGEX.test(val) || ISO_DATE_REGEX.test(val)) {
    try {
      getVietnamDayRange(val);
      return true;
    } catch {
      return false;
    }
  }

  const isoMatch = val.match(ISO_DATETIME_REGEX);
  if (isoMatch) {
    try {
      getVietnamDayRange(isoMatch[1]);
      return !isNaN(Date.parse(val));
    } catch {
      return false;
    }
  }

  return false;
}

function parseAuditDateBoundary(
  val: string,
  boundary: "start" | "end",
): Date | null {
  if (VIETNAM_DATE_REGEX.test(val) || ISO_DATE_REGEX.test(val)) {
    try {
      const range = getVietnamDayRange(val);
      return boundary === "start" ? range.startOfDay : range.endOfDay;
    } catch {
      return null;
    }
  }

  const parsed = new Date(val);
  return isNaN(parsed.getTime()) ? null : parsed;
}

function isValidAuditDateRange(data: {
  startDate?: string;
  endDate?: string;
}): boolean {
  if (data.startDate && data.endDate) {
    const start = parseAuditDateBoundary(data.startDate, "start");
    const end = parseAuditDateBoundary(data.endDate, "end");
    if (start && end) {
      return end >= start;
    }
  }
  return true;
}

function createAuditDateField(fieldName: "startDate" | "endDate") {
  return z
    .string()
    .max(50, `${fieldName} tối đa 50 ký tự`)
    .refine(isValidAuditDate, {
      message: `${fieldName} phải là định dạng DD/MM/YYYY, YYYY-MM-DD hoặc ISO 8601 hợp lệ`,
    })
    .optional();
}

export const auditLogQuerySchema = z
  .object({
    category: z.nativeEnum(AUDIT_CATEGORY).optional(),
    actorId: uuidSchema.optional(),
    action: z.string().trim().max(100).optional(),
    status: z.nativeEnum(AUDIT_LOG_STATUS).optional(),
    targetType: z.string().trim().max(100).optional(),
    targetId: z.string().trim().max(100).optional(),
    search: z
      .string()
      .trim()
      .max(100, "Từ khóa tìm kiếm tối đa 100 ký tự")
      .optional(),
    startDate: createAuditDateField("startDate"),
    endDate: createAuditDateField("endDate"),
    page: z.coerce.number().int().positive().default(1),
    limit: z.coerce.number().int().positive().max(100).default(20),
    sortBy: z
      .enum(["createdAt", "action", "targetType"])
      .default("createdAt"),
    order: z.enum(["asc", "desc"]).default("desc"),
  })
  .refine(isValidAuditDateRange, {
    message: "endDate phải lớn hơn hoặc bằng startDate",
    path: ["endDate"],
  });

export const auditLogIdParamSchema = z.object({
  id: uuidSchema,
});

export const auditLogResourceParamSchema = z.object({
  targetType: z.string().trim().min(1, "targetType không được để trống").max(100),
  targetId: z.string().trim().min(1, "targetId không được để trống").max(100),
});

export const exportAuditLogSchema = z
  .object({
    format: z.nativeEnum(AUDIT_EXPORT_FORMAT).default("csv"),
    category: z.nativeEnum(AUDIT_CATEGORY).optional(),
    actorId: uuidSchema.optional(),
    action: z.string().trim().max(100).optional(),
    status: z.nativeEnum(AUDIT_LOG_STATUS).optional(),
    targetType: z.string().trim().max(100).optional(),
    targetId: z.string().trim().max(100).optional(),
    search: z.string().trim().max(100).optional(),
    startDate: createAuditDateField("startDate"),
    endDate: createAuditDateField("endDate"),
  })
  .refine(isValidAuditDateRange, {
    message: "endDate phải lớn hơn hoặc bằng startDate",
    path: ["endDate"],
  });

export const auditSummaryQuerySchema = z
  .object({
    startDate: createAuditDateField("startDate"),
    endDate: createAuditDateField("endDate"),
  })
  .refine(isValidAuditDateRange, {
    message: "endDate phải lớn hơn hoặc bằng startDate",
    path: ["endDate"],
  });

export const resourceAuditTrailQuerySchema = z.object({
  limit: z.coerce.number().int().positive().max(200).default(50).optional(),
});

