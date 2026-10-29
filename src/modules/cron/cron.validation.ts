import { z } from "zod";
import { CRON_JOB_NAMES } from "../../common/constants/cron.constant";

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
