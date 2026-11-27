import {
  CronJobName,
  CronJobStatus,
  CronScheduleConfig,
} from "../../common/constants/cron.constant";

export interface CronJobDefaultParamsDto {
  retentionDays?: number;
  maxAgeHours?: number;
}

export interface StoredCronJobConfig {
  cron: string;
  description: string;
  isEnabled: boolean;
  defaultParams: CronJobDefaultParamsDto;
}

export interface CronJobLastExecutionDto {
  lastRunAt: string;
  lastStatus: CronJobStatus;
}

export interface CronJobItemDto {
  name: CronJobName;
  cron: string;
  schedule: CronScheduleConfig;
  scheduleLabel: string;
  description: string;
  isEnabled: boolean;
  defaultParams: CronJobDefaultParamsDto;
  nextRun?: string;
  lastRun?: string;
  lastRunAt: string | null;
  lastStatus: CronJobStatus;
}

export interface UpdateCronJobDto {
  schedule?: CronScheduleConfig;
  description?: string;
  isEnabled?: boolean;
  defaultParams?: CronJobDefaultParamsDto;
}

export interface TriggerCronJobDto {
  params?: Record<string, unknown>;
}

export interface ToggleCronJobResultDto {
  jobName: CronJobName;
  isEnabled: boolean;
}

export interface CronJobExecutionResultDto {
  jobName: CronJobName;
  success: boolean;
  durationMs: number;
  data?: Record<string, unknown>;
  error?: string;
}

export interface ActivitySummaryStatsDto {
  newUsersCount: number;
  activeSessionsCount: number;
  notificationsSentCount: number;
  emailsSentCount: number;
  webhookDeliveriesCount: number;
  auditLogsCount: number;
}
