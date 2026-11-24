import { z } from "zod";
import {
  CRON_JOB_NAMES,
  CRON_SCHEDULE_FREQUENCY,
} from "../../common/constants/cron.constant";

const validJobNames = Object.values(CRON_JOB_NAMES) as [string, ...string[]];

export const cronJobNameParamSchema = z.object({
  jobName: z.enum(validJobNames, {
    errorMap: () => ({
      message: `Tên job không hợp lệ. Cho phép: ${validJobNames.join(", ")}`,
    }),
  }),
});

export const triggerCronJobSchema = z.object({
  params: z
    .object({
      // SEC-18: Cận dưới tối thiểu 30 ngày chống xóa sạch Audit Logs
      retentionDays: z
        .number({
          invalid_type_error: "Số ngày lưu trữ phải là số",
        })
        .int("Số ngày lưu trữ phải là số nguyên")
        .min(
          30,
          "Thời gian lưu trữ tối thiểu phải từ 30 ngày để đảm bảo an toàn bằng chứng",
        )
        .max(
          3650,
          "Thời gian lưu trữ tối đa không vượt quá 3650 ngày (10 năm)",
        )
        .optional(),
      maxAgeHours: z
        .number({
          invalid_type_error: "Số giờ tối đa phải là số",
        })
        .int("Số giờ phải là số nguyên")
        .min(1, "Thời gian tối thiểu phải từ 1 giờ")
        .max(720, "Thời gian tối đa không vượt quá 720 giờ (30 ngày)")
        .optional(),
    })
    .passthrough()
    .optional()
    .default({}),
});

export const listCronJobsQuerySchema = z.object({
  search: z.string().optional(),
});

export const cronDefaultParamsSchema = z.object({
  // SEC-18: Cận dưới tối thiểu 30 ngày chống xóa sạch Audit Logs
  retentionDays: z
    .number({
      invalid_type_error: "Số ngày lưu trữ phải là số",
    })
    .int("Số ngày lưu trữ phải là số nguyên")
    .min(
      30,
      "Thời gian lưu trữ tối thiểu phải từ 30 ngày để đảm bảo an toàn bằng chứng",
    )
    .max(
      3650,
      "Thời gian lưu trữ tối đa không vượt quá 3650 ngày (10 năm)",
    )
    .optional(),
  maxAgeHours: z
    .number({
      invalid_type_error: "Số giờ tối đa phải là số",
    })
    .int("Số giờ phải là số nguyên")
    .min(1, "Thời gian tối thiểu phải từ 1 giờ")
    .max(720, "Thời gian tối đa không vượt quá 720 giờ (30 ngày)")
    .optional(),
});

export const cronScheduleSchema = z.discriminatedUnion("frequency", [
  z.object({
    frequency: z.literal(CRON_SCHEDULE_FREQUENCY.HOURLY),
    everyHours: z.coerce
      .number({ invalid_type_error: "Khoảng giờ lặp phải là số" })
      .int("Khoảng giờ lặp phải là số nguyên")
      .min(1, "Khoảng giờ lặp tối thiểu 1 giờ")
      .max(23, "Khoảng giờ lặp tối đa 23 giờ"),
    minute: z.coerce
      .number({ invalid_type_error: "Phút phải là số" })
      .int("Phút phải là số nguyên")
      .min(0, "Phút phải từ 0 đến 59")
      .max(59, "Phút phải từ 0 đến 59"),
  }),
  z.object({
    frequency: z.literal(CRON_SCHEDULE_FREQUENCY.DAILY),
    hour: z.coerce
      .number({ invalid_type_error: "Giờ phải là số" })
      .int("Giờ phải là số nguyên")
      .min(0, "Giờ phải từ 0 đến 23")
      .max(23, "Giờ phải từ 0 đến 23"),
    minute: z.coerce
      .number({ invalid_type_error: "Phút phải là số" })
      .int("Phút phải là số nguyên")
      .min(0, "Phút phải từ 0 đến 59")
      .max(59, "Phút phải từ 0 đến 59"),
  }),
  z.object({
    frequency: z.literal(CRON_SCHEDULE_FREQUENCY.WEEKLY),
    dayOfWeek: z.coerce
      .number({ invalid_type_error: "Thứ trong tuần phải là số" })
      .int("Thứ trong tuần phải là số nguyên")
      .min(0, "Thứ trong tuần phải từ 0 (Chủ nhật) đến 6 (Thứ 7)")
      .max(6, "Thứ trong tuần phải từ 0 (Chủ nhật) đến 6 (Thứ 7)"),
    hour: z.coerce
      .number({ invalid_type_error: "Giờ phải là số" })
      .int("Giờ phải là số nguyên")
      .min(0, "Giờ phải từ 0 đến 23")
      .max(23, "Giờ phải từ 0 đến 23"),
    minute: z.coerce
      .number({ invalid_type_error: "Phút phải là số" })
      .int("Phút phải là số nguyên")
      .min(0, "Phút phải từ 0 đến 59")
      .max(59, "Phút phải từ 0 đến 59"),
  }),
  z.object({
    frequency: z.literal(CRON_SCHEDULE_FREQUENCY.MONTHLY),
    dayOfMonth: z.coerce
      .number({ invalid_type_error: "Ngày trong tháng phải là số" })
      .int("Ngày trong tháng phải là số nguyên")
      .min(1, "Ngày trong tháng phải từ 1 đến 28")
      .max(28, "Ngày trong tháng chỉ chọn từ 1 đến 28 để đảm bảo chạy đủ mọi tháng"),
    hour: z.coerce
      .number({ invalid_type_error: "Giờ phải là số" })
      .int("Giờ phải là số nguyên")
      .min(0, "Giờ phải từ 0 đến 23")
      .max(23, "Giờ phải từ 0 đến 23"),
    minute: z.coerce
      .number({ invalid_type_error: "Phút phải là số" })
      .int("Phút phải là số nguyên")
      .min(0, "Phút phải từ 0 đến 59")
      .max(59, "Phút phải từ 0 đến 59"),
  }),
]);

export const updateCronJobSchema = z
  .object({
    schedule: cronScheduleSchema.optional(),
    description: z
      .string({ invalid_type_error: "Mô tả tác vụ phải là chuỗi ký tự" })
      .trim()
      .min(1, "Mô tả tác vụ không được để trống")
      .max(500, "Mô tả tác vụ tối đa 500 ký tự")
      .optional(),
    isEnabled: z
      .boolean({ invalid_type_error: "Trạng thái bật/tắt phải là boolean" })
      .optional(),
    defaultParams: cronDefaultParamsSchema.optional(),
  })
  .refine((data) => Object.keys(data).length > 0, {
    message:
      "Cần cung cấp ít nhất một trường để cập nhật (schedule, description, isEnabled hoặc defaultParams)",
  });
