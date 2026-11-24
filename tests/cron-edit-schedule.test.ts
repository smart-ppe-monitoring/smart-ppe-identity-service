import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  CRON_JOB_NAMES,
  CRON_SCHEDULE_FREQUENCY,
  buildCronFromSchedule,
  formatCronScheduleLabel,
  parseScheduleFromCron,
} from "../src/common/constants/cron.constant";
import { AUDIT_ACTION } from "../src/common/constants/audit-log.constant";
import { AppError } from "../src/common/errors/app-error";
import { ERROR_CODE } from "../src/common/errors/error-code";
import { updateCronJobSchema } from "../src/modules/cron/cron.validation";
import { CronService } from "../src/modules/cron/cron.service";
import cronRouter from "../src/modules/cron/cron.route";

describe("Cron Job Visual Schedule Edit & Persistence Suite", () => {
  it("1. Converts visual schedule configs to 5-field cron expressions and round-trips cleanly", () => {
    const hourly = {
      frequency: CRON_SCHEDULE_FREQUENCY.HOURLY,
      everyHours: 6,
      minute: 15,
    } as const;
    assert.equal(buildCronFromSchedule(hourly), "15 */6 * * *");
    assert.deepEqual(parseScheduleFromCron("15 */6 * * *"), hourly);
    assert.equal(formatCronScheduleLabel(hourly), "Mỗi 6 giờ (phút :15) (UTC+7)");

    const daily = {
      frequency: CRON_SCHEDULE_FREQUENCY.DAILY,
      hour: 2,
      minute: 5,
    } as const;
    assert.equal(buildCronFromSchedule(daily), "5 2 * * *");
    assert.deepEqual(parseScheduleFromCron("5 2 * * *"), daily);
    assert.equal(formatCronScheduleLabel(daily), "02:05 hàng ngày (UTC+7)");

    const weekly = {
      frequency: CRON_SCHEDULE_FREQUENCY.WEEKLY,
      dayOfWeek: 1,
      hour: 8,
      minute: 0,
    } as const;
    assert.equal(buildCronFromSchedule(weekly), "0 8 * * 1");
    assert.deepEqual(parseScheduleFromCron("0 8 * * 1"), weekly);
    assert.equal(formatCronScheduleLabel(weekly), "08:00 Thứ 2 hàng tuần (UTC+7)");

    const monthly = {
      frequency: CRON_SCHEDULE_FREQUENCY.MONTHLY,
      dayOfMonth: 15,
      hour: 23,
      minute: 45,
    } as const;
    assert.equal(buildCronFromSchedule(monthly), "45 23 15 * *");
    assert.deepEqual(parseScheduleFromCron("45 23 15 * *"), monthly);
    assert.equal(formatCronScheduleLabel(monthly), "23:45 ngày 15 hàng tháng (UTC+7)");
  });

  it("2. Validates updateCronJobSchema visual schedule & SEC-18 retentionDays bounds", () => {
    assert.equal(updateCronJobSchema.safeParse({}).success, false);

    assert.equal(
      updateCronJobSchema.safeParse({
        schedule: {
          frequency: CRON_SCHEDULE_FREQUENCY.MONTHLY,
          dayOfMonth: 31,
          hour: 1,
          minute: 0,
        },
      }).success,
      false,
    );

    assert.equal(
      updateCronJobSchema.safeParse({
        defaultParams: { retentionDays: 20 },
      }).success,
      false,
    );

    const ok = updateCronJobSchema.safeParse({
      schedule: {
        frequency: CRON_SCHEDULE_FREQUENCY.WEEKLY,
        dayOfWeek: 5,
        hour: 18,
        minute: 30,
      },
      description: "Tổng hợp báo cáo chiều Thứ 6",
      defaultParams: { retentionDays: 90 },
    });
    assert.equal(ok.success, true);
  });

  it("3. CronService.updateJob converts schedule, persists config, updates BullMQ dynamically, and uses stored defaultParams", async () => {
    const storedConfigs: Record<string, any> = {};
    const auditLogs: any[] = [];
    const enabledCalls: Array<{ jobName: string; options: any }> = [];
    const disabledCalls: string[] = [];
    let deletedCutoff: Date | null = null;

    const mockRepo = {
      findAllJobConfigs: async () => storedConfigs,
      upsertJobConfig: async (jobName: string, config: any) => {
        storedConfigs[jobName] = config;
      },
      createAuditLog: async (entry: any) => {
        auditLogs.push(entry);
      },
      deleteAuditLogsOlderThan: async (cutoff: Date) => {
        deletedCutoff = cutoff;
        return 12;
      },
    };

    const mockQueue = {
      enableJobScheduler: async (jobName: string, options?: any) => {
        enabledCalls.push({ jobName, options });
      },
      disableJobScheduler: async (jobName: string) => {
        disabledCalls.push(jobName);
      },
      registerSchedules: async () => {},
    };

    const service = new CronService(mockRepo as any, {} as any, mockQueue as any);

    const updated = await service.updateJob(
      CRON_JOB_NAMES.CLEANUP_AUDIT_LOGS,
      {
        schedule: {
          frequency: CRON_SCHEDULE_FREQUENCY.WEEKLY,
          dayOfWeek: 0,
          hour: 3,
          minute: 15,
        },
        description: "Dọn dẹp Audit Logs vào 03:15 Chủ nhật hàng tuần",
        defaultParams: { retentionDays: 90 },
      },
      { actorId: "admin-1" },
    );

    assert.equal(updated.cron, "15 3 * * 0");
    assert.equal(updated.scheduleLabel, "03:15 Chủ nhật hàng tuần (UTC+7)");
    assert.deepEqual(updated.defaultParams, { retentionDays: 90 });
    assert.equal(updated.isEnabled, true);
    assert.equal(storedConfigs[CRON_JOB_NAMES.CLEANUP_AUDIT_LOGS].cron, "15 3 * * 0");
    assert.equal(enabledCalls.length, 1);
    assert.equal(enabledCalls[0].options.cron, "15 3 * * 0");
    assert.deepEqual(enabledCalls[0].options.params, { retentionDays: 90 });
    assert.equal(auditLogs[0].action, AUDIT_ACTION.UPDATE_CRON_JOB);

    // Reload via fresh CronService instance backed by the same DB store
    const restartedService = new CronService(mockRepo as any, {} as any, mockQueue as any);
    const listed = await restartedService.listJobs("Chủ nhật");
    assert.equal(listed.length, 1);
    assert.equal(listed[0].cron, "15 3 * * 0");
    assert.deepEqual(listed[0].defaultParams, { retentionDays: 90 });

    // Trigger without explicit params -> uses stored 90 days default
    const execResult = await restartedService.triggerJob(CRON_JOB_NAMES.CLEANUP_AUDIT_LOGS, {});
    assert.equal(execResult.data?.retentionDays, 90);
    assert.ok(deletedCutoff);

    // Toggle off & back on -> re-registers custom cron and params (not default 0 2 * * *)
    const offRes = await restartedService.toggleJob(CRON_JOB_NAMES.CLEANUP_AUDIT_LOGS);
    assert.equal(offRes.isEnabled, false);
    assert.deepEqual(disabledCalls, [CRON_JOB_NAMES.CLEANUP_AUDIT_LOGS]);

    const onRes = await restartedService.toggleJob(CRON_JOB_NAMES.CLEANUP_AUDIT_LOGS);
    assert.equal(onRes.isEnabled, true);
    assert.equal(enabledCalls[1].options.cron, "15 3 * * 0");
    assert.deepEqual(enabledCalls[1].options.params, { retentionDays: 90 });

    // SEC-18 defense-in-depth inside updateJob
    await assert.rejects(
      () =>
        restartedService.updateJob(CRON_JOB_NAMES.CLEANUP_AUDIT_LOGS, {
          defaultParams: { retentionDays: 10 },
        }),
      (err: AppError) =>
        err.statusCode === 400 && err.code === ERROR_CODE.VALIDATION_ERROR,
    );
  });

  it("4. Registers PATCH and PUT /jobs/:jobName routes on cronRouter", () => {
    const stack = (cronRouter as any).stack as any[];
    const hasPatch = stack.some(
      (l) => l.route?.path === "/jobs/:jobName" && l.route?.methods?.patch,
    );
    const hasPut = stack.some(
      (l) => l.route?.path === "/jobs/:jobName" && l.route?.methods?.put,
    );
    assert.equal(hasPatch, true);
    assert.equal(hasPut, true);
  });
});
