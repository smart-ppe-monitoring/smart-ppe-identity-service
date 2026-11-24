export const CRON_QUEUE_NAME = "cron-scheduler-queue";

export const CRON_JOB_NAMES = {
  CLEANUP_AUDIT_LOGS: "cleanup-audit-logs",
  CLEANUP_UNCONFIRMED_UPLOADS: "cleanup-unconfirmed-uploads",
  CLEANUP_EXPIRED_TOKENS: "cleanup-expired-tokens",
  DAILY_SUMMARY_DIGEST: "daily-summary-digest",
  WEEKLY_SUMMARY_DIGEST: "weekly-summary-digest",
} as const;

export type CronJobName = (typeof CRON_JOB_NAMES)[keyof typeof CRON_JOB_NAMES];

export const DEFAULT_CRON_SCHEDULES: Record<
  CronJobName,
  { cron: string; description: string }
> = {
  "cleanup-audit-logs": {
    cron: "0 2 * * *", // Daily at 02:00 AM Asia/Ho_Chi_Minh (UTC+7)
    description: "Dọn dẹp các bản ghi Audit Logs cũ hơn 30 ngày",
  },
  "cleanup-unconfirmed-uploads": {
    cron: "0 3 * * *", // Daily at 03:00 AM Asia/Ho_Chi_Minh (UTC+7)
    description:
      "Quét và xóa các file upload rác/không xác nhận trên Cloudflare R2 / S3",
  },
  "cleanup-expired-tokens": {
    cron: "0 4 * * *", // Daily at 04:00 AM Asia/Ho_Chi_Minh (UTC+7)
    description:
      "Dọn dẹp các Refresh Tokens, Verification Tokens và Password Reset Tokens đã hết hạn",
  },
  "daily-summary-digest": {
    cron: "0 8 * * *", // Daily at 08:00 AM Asia/Ho_Chi_Minh (UTC+7)
    description:
      "Tổng hợp số liệu hoạt động trong ngày và gửi email báo cáo tới Quản trị viên",
  },
  "weekly-summary-digest": {
    cron: "0 8 * * 1", // Mondays at 08:00 AM Asia/Ho_Chi_Minh (UTC+7)
    description:
      "Tổng hợp số liệu hoạt động trong tuần và gửi email báo cáo tới Quản trị viên",
  },
};

export const DEFAULT_AUDIT_LOG_RETENTION_DAYS = 30;
export const DEFAULT_UNCONFIRMED_UPLOAD_MAX_AGE_HOURS = 24;

export const CRON_CONFIG_KEY_PREFIX = "cron.job.";
export const CRON_CONFIG_CATEGORY = "CRON";

export const CRON_SCHEDULE_FREQUENCY = {
  HOURLY: "HOURLY",
  DAILY: "DAILY",
  WEEKLY: "WEEKLY",
  MONTHLY: "MONTHLY",
} as const;

export type CronScheduleFrequency =
  (typeof CRON_SCHEDULE_FREQUENCY)[keyof typeof CRON_SCHEDULE_FREQUENCY];

export type CronScheduleConfig =
  | {
      frequency: typeof CRON_SCHEDULE_FREQUENCY.HOURLY;
      everyHours: number;
      minute: number;
    }
  | {
      frequency: typeof CRON_SCHEDULE_FREQUENCY.DAILY;
      hour: number;
      minute: number;
    }
  | {
      frequency: typeof CRON_SCHEDULE_FREQUENCY.WEEKLY;
      dayOfWeek: number;
      hour: number;
      minute: number;
    }
  | {
      frequency: typeof CRON_SCHEDULE_FREQUENCY.MONTHLY;
      dayOfMonth: number;
      hour: number;
      minute: number;
    };

export const DEFAULT_CRON_PARAMS: Record<
  CronJobName,
  { retentionDays?: number; maxAgeHours?: number }
> = {
  "cleanup-audit-logs": {
    retentionDays: DEFAULT_AUDIT_LOG_RETENTION_DAYS,
  },
  "cleanup-unconfirmed-uploads": {
    maxAgeHours: DEFAULT_UNCONFIRMED_UPLOAD_MAX_AGE_HOURS,
  },
  "cleanup-expired-tokens": {},
  "daily-summary-digest": {},
  "weekly-summary-digest": {},
};

const DAY_OF_WEEK_LABELS: Record<number, string> = {
  0: "Chủ nhật",
  1: "Thứ 2",
  2: "Thứ 3",
  3: "Thứ 4",
  4: "Thứ 5",
  5: "Thứ 6",
  6: "Thứ 7",
};

function padTwo(val: number): string {
  return String(Math.max(0, Math.floor(val))).padStart(2, "0");
}

/**
 * Chuyển đổi cấu hình lịch trực quan từ giao diện sang biểu thức Cron 5 trường chuẩn (UTC+7).
 */
export function buildCronFromSchedule(schedule: CronScheduleConfig): string {
  const minute = Math.max(0, Math.min(59, Math.floor(schedule.minute)));

  switch (schedule.frequency) {
    case CRON_SCHEDULE_FREQUENCY.HOURLY: {
      const everyHours = Math.max(1, Math.min(23, Math.floor(schedule.everyHours)));
      return `${minute} */${everyHours} * * *`;
    }
    case CRON_SCHEDULE_FREQUENCY.DAILY: {
      const hour = Math.max(0, Math.min(23, Math.floor(schedule.hour)));
      return `${minute} ${hour} * * *`;
    }
    case CRON_SCHEDULE_FREQUENCY.WEEKLY: {
      const hour = Math.max(0, Math.min(23, Math.floor(schedule.hour)));
      const dayOfWeek = Math.max(0, Math.min(6, Math.floor(schedule.dayOfWeek)));
      return `${minute} ${hour} * * ${dayOfWeek}`;
    }
    case CRON_SCHEDULE_FREQUENCY.MONTHLY: {
      const hour = Math.max(0, Math.min(23, Math.floor(schedule.hour)));
      const dayOfMonth = Math.max(1, Math.min(28, Math.floor(schedule.dayOfMonth)));
      return `${minute} ${hour} ${dayOfMonth} * *`;
    }
  }
}

/**
 * Phân giải biểu thức Cron 5 trường về cấu hình lịch trực quan để hiển thị lên UI.
 */
export function parseScheduleFromCron(cron: string): CronScheduleConfig {
  const parts = (cron || "").trim().split(/\s+/);
  if (parts.length !== 5) {
    return { frequency: CRON_SCHEDULE_FREQUENCY.DAILY, hour: 0, minute: 0 };
  }

  const [minStr, hourStr, domStr, monStr, dowStr] = parts;
  const minute = /^\d+$/.test(minStr) ? Number(minStr) : 0;
  if (minute < 0 || minute > 59) {
    return { frequency: CRON_SCHEDULE_FREQUENCY.DAILY, hour: 0, minute: 0 };
  }

  const everyHoursMatch = hourStr.match(/^\*\/(\d+)$/);
  if (
    everyHoursMatch &&
    domStr === "*" &&
    monStr === "*" &&
    dowStr === "*"
  ) {
    const everyHours = Number(everyHoursMatch[1]);
    if (everyHours >= 1 && everyHours <= 23) {
      return {
        frequency: CRON_SCHEDULE_FREQUENCY.HOURLY,
        everyHours,
        minute,
      };
    }
  }

  if (/^\d+$/.test(hourStr)) {
    const hour = Number(hourStr);
    if (hour >= 0 && hour <= 23 && monStr === "*") {
      if (domStr === "*" && dowStr === "*") {
        return {
          frequency: CRON_SCHEDULE_FREQUENCY.DAILY,
          hour,
          minute,
        };
      }
      if (domStr === "*" && /^\d+$/.test(dowStr)) {
        const rawDow = Number(dowStr);
        if (rawDow >= 0 && rawDow <= 7) {
          return {
            frequency: CRON_SCHEDULE_FREQUENCY.WEEKLY,
            dayOfWeek: rawDow === 7 ? 0 : rawDow,
            hour,
            minute,
          };
        }
      }
      if (dowStr === "*" && /^\d+$/.test(domStr)) {
        const rawDom = Number(domStr);
        if (rawDom >= 1 && rawDom <= 31) {
          return {
            frequency: CRON_SCHEDULE_FREQUENCY.MONTHLY,
            dayOfMonth: Math.min(28, rawDom),
            hour,
            minute,
          };
        }
      }
    }
  }

  return { frequency: CRON_SCHEDULE_FREQUENCY.DAILY, hour: 0, minute: 0 };
}

/**
 * Tạo nhãn mô tả lịch chạy dễ đọc cho quản trị viên (múi giờ Việt Nam UTC+7).
 */
export function formatCronScheduleLabel(schedule: CronScheduleConfig): string {
  switch (schedule.frequency) {
    case CRON_SCHEDULE_FREQUENCY.HOURLY:
      return `Mỗi ${schedule.everyHours} giờ (phút :${padTwo(schedule.minute)}) (UTC+7)`;
    case CRON_SCHEDULE_FREQUENCY.DAILY:
      return `${padTwo(schedule.hour)}:${padTwo(schedule.minute)} hàng ngày (UTC+7)`;
    case CRON_SCHEDULE_FREQUENCY.WEEKLY: {
      const dayLabel = DAY_OF_WEEK_LABELS[schedule.dayOfWeek] || "Thứ 2";
      return `${padTwo(schedule.hour)}:${padTwo(schedule.minute)} ${dayLabel} hàng tuần (UTC+7)`;
    }
    case CRON_SCHEDULE_FREQUENCY.MONTHLY:
      return `${padTwo(schedule.hour)}:${padTwo(schedule.minute)} ngày ${schedule.dayOfMonth} hàng tháng (UTC+7)`;
  }
}
