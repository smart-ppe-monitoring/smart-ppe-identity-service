import { describe, it, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import crypto from "node:crypto";
import type http from "node:http";
import type { AddressInfo } from "node:net";
import app from "../src/identity.app";
import { prisma } from "../src/database/prisma.client";
import { envConfig } from "../src/config/env.config";
import { swaggerSpec } from "../src/config/swagger.config";
import { GATEWAY_HEADERS } from "../src/common/constants/gateway.constant";
import { JWT_PURPOSE } from "../src/common/constants/jwt.constant";
import { PERMISSIONS } from "../src/common/constants/permission.constant";
import { ROLES } from "../src/common/constants/role.constant";
import {
  CRON_CONFIG_CATEGORY,
  CRON_CONFIG_KEY_PREFIX,
  CRON_JOB_NAMES,
  CRON_JOB_STATUS,
  CRON_TRIGGER_SOURCE,
  DEFAULT_CRON_SCHEDULES,
} from "../src/common/constants/cron.constant";
import {
  AUDIT_ACTION,
  AUDIT_TARGET_TYPE,
} from "../src/common/constants/audit-log.constant";
import {
  EVENT_NAMES,
  OUTBOX_STATUS,
} from "../src/common/constants/event.constant";
import { SYSTEM_CONFIG_CATEGORY } from "../src/common/constants/system-config.constant";
import { CronQueueService } from "../src/common/queues/cron.queue";
import { CronController } from "../src/modules/cron/cron.controller";
import { CronRepository } from "../src/modules/cron/cron.repository";
import { CronService } from "../src/modules/cron/cron.service";
import {
  SystemConfigService,
  isReservedCronConfig,
} from "../src/modules/system-config/system-config.service";
import { permissionCacheService } from "../src/common/services/permission-cache.service";
import { jwtKeyService } from "../src/common/services/jwt-key.service";
import { AppError } from "../src/common/errors/app-error";
import { ERROR_CODE } from "../src/common/errors/error-code";

class MockRedisConnection extends EventEmitter {
  status = "wait";
  connectCalls = 0;
  private connectImpl: () => Promise<void>;

  constructor(connectImpl?: () => Promise<void>) {
    super();
    this.connectImpl =
      connectImpl ||
      (async () => {
        this.status = "ready";
        this.emit("connect");
        this.emit("ready");
      });
  }

  async connect(): Promise<void> {
    this.connectCalls += 1;
    await this.connectImpl();
  }

  disconnect(): void {
    this.status = "end";
    this.emit("close");
  }
}

describe("Issue #10: Cron Isolation, BullMQ/Cache Startup Races, Honest Results & Audit Deduplication", () => {
  describe("1. Isolation of CRON configs from SystemConfigService", () => {
    let mockDb: Map<string, any>;
    let service: SystemConfigService;

    beforeEach(() => {
      mockDb = new Map<string, any>();
      const mockRepo = {
        findByKey: async (key: string) => mockDb.get(key) || null,
        create: async (data: any) => {
          const rec = {
            id: `cfg-${mockDb.size + 1}`,
            ...data,
            createdAt: new Date(),
            updatedAt: new Date(),
          };
          mockDb.set(data.key, rec);
          return rec;
        },
        update: async (key: string, data: any) => {
          const existing = mockDb.get(key);
          const updated = { ...existing, ...data, updatedAt: new Date() };
          mockDb.set(key, updated);
          return updated;
        },
        delete: async (key: string) => {
          mockDb.delete(key);
        },
        createAuditLog: async () => {},
      };
      service = new SystemConfigService(mockRepo as any);
    });

    it("isReservedCronConfig detects cron.job.* keys and CRON category", () => {
      assert.equal(
        isReservedCronConfig({ key: `${CRON_CONFIG_KEY_PREFIX}cleanup-audit-logs` }),
        true,
      );
      assert.equal(
        isReservedCronConfig({ key: "custom.key", category: CRON_CONFIG_CATEGORY }),
        true,
      );
      assert.equal(
        isReservedCronConfig({
          key: "app.name",
          category: SYSTEM_CONFIG_CATEGORY.GENERAL,
        }),
        false,
      );
    });

    it("create/findByKey/update/delete block access to cron.job.* keys and CRON category", async () => {
      mockDb.set(`${CRON_CONFIG_KEY_PREFIX}${CRON_JOB_NAMES.CLEANUP_AUDIT_LOGS}`, {
        id: "cfg-cron-1",
        key: `${CRON_CONFIG_KEY_PREFIX}${CRON_JOB_NAMES.CLEANUP_AUDIT_LOGS}`,
        value: { cron: "0 2 * * *", isEnabled: true },
        category: CRON_CONFIG_CATEGORY,
        isPublic: false,
      });

      await assert.rejects(
        () =>
          service.create({
            key: `${CRON_CONFIG_KEY_PREFIX}new-job`,
            value: {},
            category: CRON_CONFIG_CATEGORY,
          }),
        (err: AppError) =>
          err.statusCode === 400 && err.code === ERROR_CODE.VALIDATION_ERROR,
      );

      await assert.rejects(
        () =>
          service.create({
            key: "non.cron.prefix",
            value: {},
            category: CRON_CONFIG_CATEGORY,
          }),
        (err: AppError) =>
          err.statusCode === 400 && err.code === ERROR_CODE.VALIDATION_ERROR,
      );

      await assert.rejects(
        () =>
          service.findByKey(
            `${CRON_CONFIG_KEY_PREFIX}${CRON_JOB_NAMES.CLEANUP_AUDIT_LOGS}`,
          ),
        (err: AppError) =>
          err.statusCode === 404 && err.code === ERROR_CODE.NOT_FOUND,
      );

      await assert.rejects(
        () =>
          service.update(
            `${CRON_CONFIG_KEY_PREFIX}${CRON_JOB_NAMES.CLEANUP_AUDIT_LOGS}`,
            { value: { isEnabled: false } },
          ),
        (err: AppError) =>
          err.statusCode === 404 && err.code === ERROR_CODE.NOT_FOUND,
      );

      await assert.rejects(
        () =>
          service.delete(
            `${CRON_CONFIG_KEY_PREFIX}${CRON_JOB_NAMES.CLEANUP_AUDIT_LOGS}`,
          ),
        (err: AppError) =>
          err.statusCode === 404 && err.code === ERROR_CODE.NOT_FOUND,
      );

      await service.create({
        key: "app.banner",
        value: "Hello",
        category: SYSTEM_CONFIG_CATEGORY.GENERAL,
        isPublic: true,
      });
      await assert.rejects(
        () =>
          service.update("app.banner", {
            category: CRON_CONFIG_CATEGORY,
          }),
        (err: AppError) =>
          err.statusCode === 400 && err.code === ERROR_CODE.VALIDATION_ERROR,
      );
    });
  });

  describe("2. CronQueueService Startup Race & Delayed Reconnect Sync", () => {
    it("waits for pending Redis connect() before registering schedules", async () => {
      let resolveConnect!: () => void;
      const conn = new MockRedisConnection(
        () =>
          new Promise<void>((resolve) => {
            resolveConnect = () => {
              conn.status = "ready";
              conn.emit("connect");
              conn.emit("ready");
              resolve();
            };
          }),
      );

      const upserts: string[] = [];
      const removals: string[] = [];
      const mockQueue: any = {
        upsertJobScheduler: async (name: string) => {
          upserts.push(name);
        },
        removeJobScheduler: async (name: string) => {
          removals.push(name);
        },
        close: async () => {},
      };

      const queueService = new CronQueueService({
        queue: mockQueue,
        redisConnection: conn as any,
        connectTimeoutMs: 1000,
      });

      const registerPromise = queueService.registerSchedules({
        [CRON_JOB_NAMES.CLEANUP_AUDIT_LOGS]: {
          cron: "0 2 * * *",
          isEnabled: false,
        },
      });

      // Resolve Redis connect slightly after registerSchedules() was invoked
      setTimeout(() => resolveConnect(), 20);
      await registerPromise;

      assert.deepEqual(removals, [CRON_JOB_NAMES.CLEANUP_AUDIT_LOGS]);
      assert.equal(
        upserts.length,
        Object.keys(DEFAULT_CRON_SCHEDULES).length - 1,
      );

      await queueService.close();
    });

    it("auto-registers schedules when Redis connects after initial timeout and avoids duplicate syncs", async () => {
      let rejectSlowConnect!: (err: Error) => void;
      const conn = new MockRedisConnection(
        () =>
          new Promise<void>((_resolve, reject) => {
            rejectSlowConnect = reject;
          }),
      );

      const upserts: string[] = [];
      const mockQueue: any = {
        upsertJobScheduler: async (name: string) => {
          upserts.push(name);
        },
        removeJobScheduler: async () => {},
        close: async () => {},
      };

      const queueService = new CronQueueService({
        queue: mockQueue,
        redisConnection: conn as any,
        connectTimeoutMs: 25,
      });

      // Times out cleanly during startup without registering anything yet
      await queueService.registerSchedules();
      assert.equal(upserts.length, 0);

      // Cleanly end initial stalled connect attempt and simulate Redis becoming ready later
      rejectSlowConnect(new Error("Initial connection timed out"));
      await new Promise((r) => setTimeout(r, 5));
      conn.status = "ready";
      conn.emit("connect");
      conn.emit("ready");
      await new Promise((r) => setTimeout(r, 20));

      const totalJobs = Object.keys(DEFAULT_CRON_SCHEDULES).length;
      assert.equal(upserts.length, totalJobs);

      // Spurious duplicate ready without disconnect must NOT re-register redundantly
      conn.emit("ready");
      await new Promise((r) => setTimeout(r, 20));
      assert.equal(upserts.length, totalJobs);

      // Disconnect followed by reconnect DOES re-register all schedules
      conn.emit("close");
      conn.status = "ready";
      conn.emit("ready");
      await new Promise((r) => setTimeout(r, 20));
      assert.equal(upserts.length, totalJobs * 2);

      await queueService.close();
    });
  });

  describe("3. Cache Load Retry, Real Execution Status, Honest Counts & Audit Deduplication", () => {
    it("retries DB config loading after a transient failure instead of locking defaults", async () => {
      let attempt = 0;
      const mockRepo = {
        findAllJobConfigs: async () => {
          attempt += 1;
          if (attempt === 1) {
            throw new Error("Transient DB error");
          }
          return {
            [CRON_JOB_NAMES.CLEANUP_AUDIT_LOGS]: {
              cron: "30 4 * * *",
              description: "Loaded after DB recovery",
              isEnabled: false,
              defaultParams: { retentionDays: 60 },
            },
          };
        },
        findLatestJobExecutions: async () => ({}),
      };

      const service = new CronService(
        mockRepo as any,
        {} as any,
        {
          registerSchedules: async () => {},
          enableJobScheduler: async () => {},
          disableJobScheduler: async () => {},
        } as any,
      );

      // First load encounters DB error -> falls back to default temporarily
      const firstList = await service.listJobs();
      const firstAuditJob = firstList.find(
        (j) => j.name === CRON_JOB_NAMES.CLEANUP_AUDIT_LOGS,
      )!;
      assert.equal(firstAuditJob.cron, "0 2 * * *");
      assert.equal(firstAuditJob.isEnabled, true);

      // Second call retries DB load and picks up persisted config
      const secondList = await service.listJobs();
      const secondAuditJob = secondList.find(
        (j) => j.name === CRON_JOB_NAMES.CLEANUP_AUDIT_LOGS,
      )!;
      assert.equal(attempt, 2);
      assert.equal(secondAuditJob.cron, "30 4 * * *");
      assert.equal(secondAuditJob.description, "Loaded after DB recovery");
      assert.equal(secondAuditJob.isEnabled, false);
      assert.deepEqual(secondAuditJob.defaultParams, { retentionDays: 60 });

      // Third call uses cached configs without extra DB hit
      await service.listJobs();
      assert.equal(attempt, 2);
    });

    it("tracks real lastRunAt & lastStatus (READY -> SUCCESS -> FAILED) and deduplicates manual trigger audit logs", async () => {
      const auditLogs: any[] = [];
      let failDeleteTokens = false;

      const mockRepo = {
        findAllJobConfigs: async () => ({}),
        findLatestJobExecutions: async () => ({}),
        deleteAuditLogsOlderThan: async () => 5,
        deleteExpiredTokens: async () => {
          if (failDeleteTokens) {
            throw new Error("Simulated token cleanup DB failure");
          }
          return {
            refreshTokensCount: 2,
            verificationTokensCount: 1,
            passwordResetTokensCount: 0,
          };
        },
        createAuditLog: async (entry: any) => {
          auditLogs.push({
            ...entry,
            createdAt: new Date(),
          });
        },
      };

      const service = new CronService(
        mockRepo as any,
        {} as any,
        { registerSchedules: async () => {} } as any,
      );

      // Initial state: lastRunAt = null, lastStatus = READY
      const initial = await service.listJobs();
      for (const job of initial) {
        assert.equal(job.lastRunAt, null);
        assert.equal(job.lastStatus, CRON_JOB_STATUS.READY);
      }

      // Manual trigger writes ONLY 1 audit log with full actorContext
      const actorCtx = {
        actorId: "admin-uuid-1",
        ipAddress: "10.0.0.15",
        userAgent: "TestAgent/1.0",
      };
      const execRes = await service.triggerJob(
        CRON_JOB_NAMES.CLEANUP_AUDIT_LOGS,
        { retentionDays: 45 },
        actorCtx,
      );
      assert.equal(execRes.success, true);
      assert.equal(auditLogs.length, 1);
      assert.equal(auditLogs[0].action, AUDIT_ACTION.TRIGGER_CRON_JOB);
      assert.equal(auditLogs[0].actorId, "admin-uuid-1");
      assert.equal(auditLogs[0].ipAddress, "10.0.0.15");
      assert.equal(auditLogs[0].userAgent, "TestAgent/1.0");
      assert.equal(auditLogs[0].details.status, CRON_JOB_STATUS.SUCCESS);
      assert.equal(auditLogs[0].details.triggerSource, CRON_TRIGGER_SOURCE.MANUAL);

      const afterSuccess = await service.listJobs();
      const cleanupAuditJob = afterSuccess.find(
        (j) => j.name === CRON_JOB_NAMES.CLEANUP_AUDIT_LOGS,
      )!;
      assert.ok(cleanupAuditJob.lastRunAt);
      assert.equal(cleanupAuditJob.lastStatus, CRON_JOB_STATUS.SUCCESS);

      // Failure updates status to FAILED and records 1 failed audit log
      failDeleteTokens = true;
      await assert.rejects(
        () => service.triggerJob(CRON_JOB_NAMES.CLEANUP_EXPIRED_TOKENS, {}, actorCtx),
        /Simulated token cleanup DB failure/,
      );
      assert.equal(auditLogs.length, 2);
      assert.equal(auditLogs[1].action, AUDIT_ACTION.TRIGGER_CRON_JOB);
      assert.equal(auditLogs[1].details.status, CRON_JOB_STATUS.FAILED);
      assert.match(auditLogs[1].details.error, /Simulated token cleanup DB failure/);

      const afterFail = await service.listJobs();
      const expiredTokensJob = afterFail.find(
        (j) => j.name === CRON_JOB_NAMES.CLEANUP_EXPIRED_TOKENS,
      )!;
      assert.ok(expiredTokensJob.lastRunAt);
      assert.equal(expiredTokensJob.lastStatus, CRON_JOB_STATUS.FAILED);
    });

    it("executeUploadsCleanup reports true deletedCount/failedCount when R2 fails partially or completely", async () => {
      const oldDate = new Date(Date.now() - 48 * 60 * 60 * 1000);
      const mockRepo = {
        getAllUserAvatarUrls: async () => [],
        createAuditLog: async () => {},
      };

      // Partial batch failure
      const servicePartial = new CronService(
        mockRepo as any,
        {
          listObjects: async () => [
            { key: "avatars/u1/ok.png", lastModified: oldDate },
            { key: "avatars/u2/fail.png", lastModified: oldDate },
          ],
          deleteFiles: async () => ({
            deletedKeys: ["avatars/u1/ok.png"],
            failedKeys: ["avatars/u2/fail.png"],
          }),
        } as any,
      );

      const partialRes = await servicePartial.executeUploadsCleanup(24);
      assert.equal(partialRes.scannedCount, 2);
      assert.equal(partialRes.deletedCount, 1);
      assert.equal(partialRes.failedCount, 1);
      assert.deepEqual(partialRes.deletedKeys, ["avatars/u1/ok.png"]);
      assert.deepEqual(partialRes.failedKeys, ["avatars/u2/fail.png"]);

      // Complete batch exception must report 0 deleted instead of faking success
      const serviceThrown = new CronService(
        mockRepo as any,
        {
          listObjects: async () => [
            { key: "avatars/u1/a.png", lastModified: oldDate },
          ],
          deleteFiles: async () => {
            throw new Error("R2 AccessDenied");
          },
        } as any,
      );

      const failRes = await serviceThrown.executeUploadsCleanup(24);
      assert.equal(failRes.scannedCount, 1);
      assert.equal(failRes.deletedCount, 0);
      assert.equal(failRes.failedCount, 1);
      assert.deepEqual(failRes.deletedKeys, []);
      assert.deepEqual(failRes.failedKeys, ["avatars/u1/a.png"]);
    });

    it("executeSummaryDigest counts only successful dispatches as recipientCount", async () => {
      const auditLogs: any[] = [];
      const mockRepo = {
        getActivityStats: async () => ({
          newUsersCount: 3,
          activeSessionsCount: 4,
          notificationsSentCount: 5,
          emailsSentCount: 2,
          webhookDeliveriesCount: 1,
          auditLogsCount: 10,
        }),
        findAdminUsers: async () => [
          { id: "adm-1", email: "ok@smartppe.local", fullName: "Admin OK" },
          { id: "adm-2", email: "", fullName: "No Email" },
          { id: "adm-3", email: "fail@smartppe.local", fullName: "Fail Admin" },
          {
            id: "adm-4",
            email: "disabled@smartppe.local",
            fullName: "Notifications Off",
          },
        ],
        createAuditLog: async (entry: any) => {
          auditLogs.push(entry);
        },
      };

      const mockNotifier = {
        send: async (event: any) => {
          if (event.email?.toEmail === "fail@smartppe.local") {
            throw new Error("SMTP timeout");
          }
          if (event.email?.toEmail === "disabled@smartppe.local") {
            return false;
          }
          return true;
        },
      };

      const service = new CronService(
        mockRepo as any,
        {} as any,
        { registerSchedules: async () => {} } as any,
        mockNotifier as any,
      );

      const digestRes = await service.executeSummaryDigest({ period: "DAILY" });
      assert.equal(digestRes.recipientCount, 1);
      assert.equal(digestRes.failedCount, 1);
      assert.equal(digestRes.skippedCount, 2);
      assert.equal(auditLogs.length, 1);
      assert.equal(auditLogs[0].details.recipientCount, 1);

      // Calling through triggerJob should write only 1 TRIGGER_CRON_JOB audit log
      auditLogs.length = 0;
      const triggered = await service.triggerJob(
        CRON_JOB_NAMES.DAILY_SUMMARY_DIGEST,
        {},
        { actorId: "admin-1" },
      );
      assert.equal(auditLogs.length, 1);
      assert.equal(auditLogs[0].action, AUDIT_ACTION.TRIGGER_CRON_JOB);
      assert.equal((triggered.data as any).recipientCount, 1);
    });
  });

  describe("4. CronController IP Extraction & OpenAPI Documentation", () => {
    it("ignores x-forwarded-for fallback and passes normalized req.ip via getClientIp", async () => {
      const capturedContexts: Array<Record<string, unknown>> = [];
      const mockService = {
        triggerJob: async (_name: any, _params: any, ctx: any) => {
          capturedContexts.push(ctx);
          return { jobName: _name, success: true, durationMs: 1 };
        },
        toggleJob: async (_name: any, ctx: any) => {
          capturedContexts.push(ctx);
          return { jobName: _name, isEnabled: false };
        },
        updateJob: async (_name: any, _body: any, ctx: any) => {
          capturedContexts.push(ctx);
          return { name: _name };
        },
      };

      const controller = new CronController(mockService as any);
      const fakeReq = {
        params: { jobName: CRON_JOB_NAMES.CLEANUP_EXPIRED_TOKENS },
        body: { params: {} },
        user: { id: "admin-id" },
        ip: "::ffff:127.0.0.1",
        headers: {
          "x-forwarded-for": "203.0.113.99, 10.0.0.1",
          "user-agent": "MockBrowser",
        },
        socket: { remoteAddress: "127.0.0.1" },
      } as any;
      const fakeRes = { json: () => {} } as any;
      const noopNext = () => {};

      await controller.triggerJob(fakeReq, fakeRes, noopNext);
      await controller.toggleJob(fakeReq, fakeRes, noopNext);
      await controller.updateJob(fakeReq, fakeRes, noopNext);

      assert.equal(capturedContexts.length, 3);
      for (const ctx of capturedContexts) {
        assert.equal(ctx.ipAddress, "127.0.0.1");
        assert.equal(ctx.userAgent, "MockBrowser");
      }
    });

    it("OpenAPI /cron/jobs and /cron/jobs/{jobName}/toggle reflect updated schema and DB persistence", () => {
      const paths = swaggerSpec.paths as Record<string, any>;
      const itemProps =
        paths["/cron/jobs"]?.get?.responses?.["200"]?.content?.[
          "application/json"
        ]?.schema?.properties?.data?.items?.properties;

      assert.ok(itemProps?.lastRunAt, "cronJobItem must document lastRunAt");
      assert.deepEqual(itemProps?.lastStatus?.enum, [
        CRON_JOB_STATUS.READY,
        CRON_JOB_STATUS.SUCCESS,
        CRON_JOB_STATUS.FAILED,
      ]);

      const toggleDesc =
        paths["/cron/jobs/{jobName}/toggle"]?.patch?.description || "";
      assert.ok(!toggleDesc.includes("in-memory"));
    });
  });

  describe("5. Live HTTP + PostgreSQL (ppe_identity_db) Integration Tests", () => {
    let dbAvailable = false;
    let server: http.Server | null = null;
    let baseUrl = "";
    let adminToken = "";
    let adminUserId = "";
    let createdTempRoleId: string | null = null;
    const createdUserIds: string[] = [];
    const createdOutboxIds: string[] = [];
    const testStartTime = new Date();
    let originalCronConfigRow: any = null;
    let hadOriginalCronConfigRow = false;

    const suffix = crypto.randomBytes(4).toString("hex");
    const targetJobKey = `${CRON_CONFIG_KEY_PREFIX}${CRON_JOB_NAMES.CLEANUP_EXPIRED_TOKENS}`;

    async function requestApi(
      method: "GET" | "POST" | "PUT" | "PATCH",
      path: string,
      body?: unknown,
      extraHeaders: Record<string, string> = {},
    ) {
      const headers: Record<string, string> = {
        authorization: `Bearer ${adminToken}`,
        ...extraHeaders,
      };
      if (envConfig.gateway.internalSecret) {
        headers[GATEWAY_HEADERS.INTERNAL_SECRET] =
          envConfig.gateway.internalSecret;
      }
      if (body !== undefined) {
        headers["content-type"] = "application/json";
      }
      const res = await fetch(`${baseUrl}${path}`, {
        method,
        headers,
        body: body !== undefined ? JSON.stringify(body) : undefined,
      });
      const text = await res.text();
      return {
        status: res.status,
        body: text ? JSON.parse(text) : null,
      };
    }

    before(async () => {
      try {
        await prisma.$queryRaw`SELECT 1`;
        dbAvailable = true;
      } catch {
        dbAvailable = false;
        return;
      }

      permissionCacheService.clear();

      originalCronConfigRow = await prisma.systemConfig.findUnique({
        where: { key: targetJobKey },
      });
      hadOriginalCronConfigRow = Boolean(originalCronConfigRow);

      let adminRole = await prisma.role.findFirst({
        where: { name: ROLES.ADMIN },
      });
      if (!adminRole) {
        adminRole = await prisma.role.create({
          data: {
            name: ROLES.ADMIN,
            description: "Temporary test admin role",
            isSystem: true,
          },
        });
        createdTempRoleId = adminRole.id;
      }

      const adminUser = await prisma.user.create({
        data: {
          email: `it-issue10-admin-${suffix}@smartppe.local`,
          fullName: `Issue10 Admin ${suffix}`,
          roleId: adminRole.id,
          isActive: true,
          deletedAt: null,
          siteIds: [],
        },
      });
      adminUserId = adminUser.id;
      createdUserIds.push(adminUser.id);

      adminToken = jwtKeyService.signAccessToken({
        id: adminUser.id,
        email: adminUser.email!,
        role: ROLES.ADMIN,
        roleId: adminRole.id,
        permissions: [
          PERMISSIONS.SYSTEM_CONFIG_READ,
          PERMISSIONS.SYSTEM_CONFIG_WRITE,
          PERMISSIONS.CRON_JOB_READ,
          PERMISSIONS.CRON_JOB_MANAGE,
        ],
        purpose: JWT_PURPOSE.ACCESS,
        mustChangePassword: false,
      });

      server = await new Promise<http.Server>((resolve) => {
        const s = app.listen(0, "127.0.0.1", () => resolve(s));
      });
      const addr = server.address() as AddressInfo;
      baseUrl = `http://127.0.0.1:${addr.port}`;
    });

    after(async () => {
      try {
        if (dbAvailable) {
          if (adminUserId) {
            await prisma.auditLog
              .deleteMany({
                where: {
                  actorId: adminUserId,
                  createdAt: { gte: testStartTime },
                },
              })
              .catch(() => {});
          }
          if (createdOutboxIds.length > 0) {
            await prisma.outboxEvent
              .deleteMany({ where: { id: { in: createdOutboxIds } } })
              .catch(() => {});
          }
          if (hadOriginalCronConfigRow && originalCronConfigRow) {
            await prisma.systemConfig
              .upsert({
                where: { key: targetJobKey },
                update: {
                  value: originalCronConfigRow.value,
                  description: originalCronConfigRow.description,
                  category: originalCronConfigRow.category,
                  isPublic: originalCronConfigRow.isPublic,
                },
                create: {
                  key: targetJobKey,
                  value: originalCronConfigRow.value,
                  description: originalCronConfigRow.description,
                  category: originalCronConfigRow.category,
                  isPublic: originalCronConfigRow.isPublic,
                },
              })
              .catch(() => {});
          } else {
            await prisma.systemConfig
              .deleteMany({ where: { key: targetJobKey } })
              .catch(() => {});
          }
          if (createdUserIds.length > 0) {
            await prisma.user
              .deleteMany({ where: { id: { in: createdUserIds } } })
              .catch(() => {});
          }
          if (createdTempRoleId) {
            await prisma.role
              .deleteMany({ where: { id: createdTempRoleId } })
              .catch(() => {});
          }
        }
      } finally {
        permissionCacheService.clear();
        if (server) {
          await new Promise<void>((resolve) => {
            server!.close(() => resolve());
          });
        }
        await prisma.$disconnect().catch(() => {});
      }
    });

    it("isolates cron.job.* rows from /api/v1/system/configs and rejects direct CRON tampering", async (t) => {
      if (!dbAvailable) {
        t.skip("PostgreSQL ppe_identity_db is unavailable");
        return;
      }

      // Ensure a cron.job.* row with category="CRON" exists in DB
      const updateCronRes = await requestApi(
        "PUT",
        `/api/v1/cron/jobs/${CRON_JOB_NAMES.CLEANUP_EXPIRED_TOKENS}`,
        {
          description: `Issue10 persisted cron ${suffix}`,
        },
      );
      assert.strictEqual(updateCronRes.status, 200);

      const dbRow = await prisma.systemConfig.findUnique({
        where: { key: targetJobKey },
      });
      assert.ok(dbRow);
      assert.strictEqual(dbRow.category, CRON_CONFIG_CATEGORY);

      // Listing /system/configs must exclude CRON records across default, category, and search queries
      for (const queryUrl of [
        "/api/v1/system/configs",
        "/api/v1/system/configs?page=1&limit=100",
        `/api/v1/system/configs?category=${CRON_CONFIG_CATEGORY}`,
        "/api/v1/system/configs?search=cron.job",
      ]) {
        const listRes = await requestApi("GET", queryUrl);
        assert.strictEqual(listRes.status, 200);
        const items = (listRes.body.data || []) as any[];
        assert.strictEqual(
          items.some(
            (item) =>
              item.category === CRON_CONFIG_CATEGORY ||
              String(item.key).startsWith(CRON_CONFIG_KEY_PREFIX),
          ),
          false,
          `Unexpected CRON leak in ${queryUrl}`,
        );
      }

      // Direct GET/PUT on /system/configs/cron.job.* returns 404
      const getCronAsSystem = await requestApi(
        "GET",
        `/api/v1/system/configs/${encodeURIComponent(targetJobKey)}`,
      );
      assert.strictEqual(getCronAsSystem.status, 404);

      const putCronAsSystem = await requestApi(
        "PUT",
        `/api/v1/system/configs/${encodeURIComponent(targetJobKey)}`,
        { value: { isEnabled: false } },
      );
      assert.strictEqual(putCronAsSystem.status, 404);

      // POST /system/configs with cron.job.* key or CRON category returns 400
      const postCronRes = await requestApi("POST", "/api/v1/system/configs", {
        key: `${CRON_CONFIG_KEY_PREFIX}rogue`,
        value: {},
        category: SYSTEM_CONFIG_CATEGORY.GENERAL,
      });
      assert.strictEqual(postCronRes.status, 400);
    });

    it("triggers cron job via HTTP with 1 deduplicated audit log, safe IP, and real persisted lastStatus", async (t) => {
      if (!dbAvailable) {
        t.skip("PostgreSQL ppe_identity_db is unavailable");
        return;
      }

      const beforeTrigger = new Date();
      const triggerRes = await requestApi(
        "POST",
        `/api/v1/cron/jobs/${CRON_JOB_NAMES.CLEANUP_EXPIRED_TOKENS}/trigger`,
        { params: {} },
        { "x-forwarded-for": "203.0.113.77" },
      );
      assert.strictEqual(triggerRes.status, 200);
      assert.strictEqual(triggerRes.body.data.success, true);

      // Only 1 audit log written for this trigger
      const triggerLogs = await prisma.auditLog.findMany({
        where: {
          targetType: AUDIT_TARGET_TYPE.CRON_JOB,
          targetId: CRON_JOB_NAMES.CLEANUP_EXPIRED_TOKENS,
          actorId: adminUserId,
          createdAt: { gte: beforeTrigger },
        },
      });
      assert.strictEqual(triggerLogs.length, 1);
      assert.strictEqual(triggerLogs[0].action, AUDIT_ACTION.TRIGGER_CRON_JOB);
      assert.notStrictEqual(triggerLogs[0].ipAddress, "203.0.113.77");
      const details = triggerLogs[0].details as Record<string, any>;
      assert.strictEqual(details.status, CRON_JOB_STATUS.SUCCESS);
      assert.strictEqual(details.triggerSource, CRON_TRIGGER_SOURCE.MANUAL);

      // GET /api/v1/cron/jobs reflects real lastRunAt & lastStatus
      const listRes = await requestApi("GET", "/api/v1/cron/jobs");
      assert.strictEqual(listRes.status, 200);
      const tokenJob = (listRes.body.data as any[]).find(
        (j) => j.name === CRON_JOB_NAMES.CLEANUP_EXPIRED_TOKENS,
      );
      assert.ok(tokenJob);
      assert.ok(tokenJob.lastRunAt);
      assert.strictEqual(tokenJob.lastStatus, CRON_JOB_STATUS.SUCCESS);

      // Fresh CronService queries PostgreSQL via findLatestJobExecutions
      const freshService = new CronService(new CronRepository());
      const freshJobs = await freshService.listJobs();
      const freshTokenJob = freshJobs.find(
        (j) => j.name === CRON_JOB_NAMES.CLEANUP_EXPIRED_TOKENS,
      );
      assert.ok(freshTokenJob?.lastRunAt);
      assert.strictEqual(freshTokenJob?.lastStatus, CRON_JOB_STATUS.SUCCESS);
    });

    it("CronRepository.getActivityStats aggregates published outbox notification/email events", async (t) => {
      if (!dbAvailable) {
        t.skip("PostgreSQL ppe_identity_db is unavailable");
        return;
      }

      const start = new Date(Date.now() - 60_000);
      const emailEvent = await prisma.outboxEvent.create({
        data: {
          eventType: EVENT_NAMES.AUTH_VERIFICATION_REQUESTED,
          payload: { test: suffix },
          status: OUTBOX_STATUS.PUBLISHED,
          publishedAt: new Date(),
        },
      });
      const alertEvent = await prisma.outboxEvent.create({
        data: {
          eventType: EVENT_NAMES.PPE_VIOLATION_DETECTED,
          payload: { test: suffix },
          status: OUTBOX_STATUS.PUBLISHED,
          publishedAt: new Date(),
        },
      });
      createdOutboxIds.push(emailEvent.id, alertEvent.id);

      const repo = new CronRepository();
      const stats = await repo.getActivityStats(start, new Date(Date.now() + 60_000));
      assert.ok(stats.emailsSentCount >= 1);
      assert.ok(stats.notificationsSentCount >= 2);
    });
  });
});
