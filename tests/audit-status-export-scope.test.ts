import { describe, it, beforeEach, before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import type http from "node:http";
import type { AddressInfo } from "node:net";
import { Prisma } from "@prisma/client";
import app from "../src/identity.app";
import { prisma } from "../src/database/prisma.client";
import { jwtKeyService } from "../src/common/services/jwt-key.service";
import { envConfig } from "../src/config/env.config";
import { GATEWAY_HEADERS } from "../src/common/constants/gateway.constant";
import { JWT_PURPOSE } from "../src/common/constants/jwt.constant";
import { PERMISSIONS } from "../src/common/constants/permission.constant";
import { ERROR_CODE } from "../src/common/errors/error-code";
import { ROLES } from "../src/common/constants/role.constant";
import { permissionCacheService } from "../src/common/services/permission-cache.service";
import { swaggerSpec } from "../src/config/swagger.config";
import {
  AUDIT_ACTION,
  AUDIT_DEPRECATION_NOTICE,
  AUDIT_LOG_STATUS,
  AUDIT_SCOPE,
  deriveAuditLogStatus,
} from "../src/modules/audit/audit.constant";
import {
  auditLogQuerySchema,
  auditSummaryQuerySchema,
  exportAuditLogSchema,
} from "../src/modules/audit/audit.validation";
import { AuditRepository } from "../src/modules/audit/audit.repository";
import { AuditService } from "../src/modules/audit/audit.service";

describe("Issue #6: Audit Log Status Filter, Export Date Validation, & Incident-Reviews Scope", () => {
  describe("1. deriveAuditLogStatus Unit Tests", () => {
    it("should classify details.status FAILED and ERROR (case-insensitive / trimmed) as FAILED", () => {
      assert.strictEqual(
        deriveAuditLogStatus("UPDATE_SYSTEM_CONFIG", { status: "FAILED" }),
        AUDIT_LOG_STATUS.FAILED,
      );
      assert.strictEqual(
        deriveAuditLogStatus("UPDATE_SYSTEM_CONFIG", { status: "failed" }),
        AUDIT_LOG_STATUS.FAILED,
      );
      assert.strictEqual(
        deriveAuditLogStatus("UPDATE_SYSTEM_CONFIG", { status: " ERROR " }),
        AUDIT_LOG_STATUS.FAILED,
      );
      assert.strictEqual(
        deriveAuditLogStatus("UPDATE_SYSTEM_CONFIG", { status: "SUCCESS" }),
        AUDIT_LOG_STATUS.SUCCESS,
      );
      assert.strictEqual(
        deriveAuditLogStatus("UPDATE_SYSTEM_CONFIG", { status: "OK" }),
        AUDIT_LOG_STATUS.SUCCESS,
      );
    });

    it("should classify details.success === false as FAILED and true as SUCCESS", () => {
      assert.strictEqual(
        deriveAuditLogStatus("CREATE_ROLE", { success: false }),
        AUDIT_LOG_STATUS.FAILED,
      );
      assert.strictEqual(
        deriveAuditLogStatus("CREATE_ROLE", { success: true }),
        AUDIT_LOG_STATUS.SUCCESS,
      );
    });

    it("should classify non-empty details.errorMessage as FAILED and empty/whitespace as SUCCESS", () => {
      assert.strictEqual(
        deriveAuditLogStatus("TRIGGER_CRON_JOB", { errorMessage: "Timeout" }),
        AUDIT_LOG_STATUS.FAILED,
      );
      assert.strictEqual(
        deriveAuditLogStatus("TRIGGER_CRON_JOB", { errorMessage: "" }),
        AUDIT_LOG_STATUS.SUCCESS,
      );
      assert.strictEqual(
        deriveAuditLogStatus("TRIGGER_CRON_JOB", { errorMessage: "   " }),
        AUDIT_LOG_STATUS.SUCCESS,
      );
    });

    it("should classify truthy/object/non-empty details.error as FAILED and null/false/empty as SUCCESS", () => {
      assert.strictEqual(
        deriveAuditLogStatus("VERIFY_2FA_LOGIN", { error: "err" }),
        AUDIT_LOG_STATUS.FAILED,
      );
      assert.strictEqual(
        deriveAuditLogStatus("VERIFY_2FA_LOGIN", { error: true }),
        AUDIT_LOG_STATUS.FAILED,
      );
      assert.strictEqual(
        deriveAuditLogStatus("VERIFY_2FA_LOGIN", { error: { code: 500 } }),
        AUDIT_LOG_STATUS.FAILED,
      );
      assert.strictEqual(
        deriveAuditLogStatus("VERIFY_2FA_LOGIN", { error: 1 }),
        AUDIT_LOG_STATUS.FAILED,
      );

      assert.strictEqual(
        deriveAuditLogStatus("VERIFY_2FA_LOGIN", { error: false }),
        AUDIT_LOG_STATUS.SUCCESS,
      );
      assert.strictEqual(
        deriveAuditLogStatus("VERIFY_2FA_LOGIN", { error: null }),
        AUDIT_LOG_STATUS.SUCCESS,
      );
      assert.strictEqual(
        deriveAuditLogStatus("VERIFY_2FA_LOGIN", { error: "" }),
        AUDIT_LOG_STATUS.SUCCESS,
      );
      assert.strictEqual(
        deriveAuditLogStatus("VERIFY_2FA_LOGIN", { error: "   " }),
        AUDIT_LOG_STATUS.SUCCESS,
      );
      assert.strictEqual(
        deriveAuditLogStatus("VERIFY_2FA_LOGIN", { error: undefined }),
        AUDIT_LOG_STATUS.SUCCESS,
      );
    });

    it("should classify ACCOUNT_LOCKED and failure action suffixes as FAILED without false-matching substrings", () => {
      for (const action of [
        AUDIT_ACTION.ACCOUNT_LOCKED,
        "LOGIN_FAILED",
        "LOGIN_FAIL",
        "UPLOAD_ERROR",
        "ACCESS_DENIED",
        "REQUEST_REJECTED",
        "login_failed",
      ]) {
        assert.strictEqual(
          deriveAuditLogStatus(action, null),
          AUDIT_LOG_STATUS.FAILED,
          `Expected ${action} to be FAILED`,
        );
      }

      for (const action of [
        AUDIT_ACTION.CREATE_ROLE,
        AUDIT_ACTION.UPDATE_SYSTEM_CONFIG,
        "TERROR_TEST",
      ]) {
        assert.strictEqual(
          deriveAuditLogStatus(action, null),
          AUDIT_LOG_STATUS.SUCCESS,
          `Expected ${action} to be SUCCESS`,
        );
      }
    });

    it("should handle null, array, or scalar details safely without throwing", () => {
      assert.strictEqual(
        deriveAuditLogStatus("CREATE_ROLE", null),
        AUDIT_LOG_STATUS.SUCCESS,
      );
      assert.strictEqual(
        deriveAuditLogStatus("CREATE_ROLE", ["bad"] as unknown as Record<string, unknown>),
        AUDIT_LOG_STATUS.SUCCESS,
      );
      assert.strictEqual(
        deriveAuditLogStatus("LOGIN_FAILED", "scalar" as unknown as Record<string, unknown>),
        AUDIT_LOG_STATUS.FAILED,
      );
    });
  });

  describe("2. Validation Schemas (status & export date range)", () => {
    it("auditLogQuerySchema and exportAuditLogSchema should accept SUCCESS, FAILED, and undefined status", () => {
      for (const status of [undefined, "SUCCESS", "FAILED"]) {
        const listParsed = auditLogQuerySchema.parse({ status });
        assert.strictEqual(listParsed.status, status);

        const exportParsed = exportAuditLogSchema.parse({ status });
        assert.strictEqual(exportParsed.status, status);
      }
    });

    it("auditLogQuerySchema and exportAuditLogSchema should reject invalid status values", () => {
      for (const badStatus of ["failed", "ERROR", "", "INVALID"]) {
        assert.strictEqual(
          auditLogQuerySchema.safeParse({ status: badStatus }).success,
          false,
        );
        assert.strictEqual(
          exportAuditLogSchema.safeParse({ status: badStatus }).success,
          false,
        );
      }
    });

    it("exportAuditLogSchema, auditLogQuerySchema, and auditSummaryQuerySchema should accept valid date formats and ranges", () => {
      const validPayloads = [
        { startDate: "2026-11-20", endDate: "2026-11-26" },
        { startDate: "20/11/2026", endDate: "26/11/2026" },
        { startDate: "2026-11-26", endDate: "2026-11-26" },
        { startDate: "26/11/2026", endDate: "26/11/2026" },
        {
          startDate: "2026-11-26T00:00:00Z",
          endDate: "2026-11-26T23:59:59Z",
        },
        {
          startDate: "2026-11-26T10:00:00Z",
          endDate: "2026-11-26T10:00:00Z",
        },
      ];

      for (const payload of validPayloads) {
        assert.strictEqual(
          exportAuditLogSchema.safeParse(payload).success,
          true,
          `exportAuditLogSchema failed for ${JSON.stringify(payload)}`,
        );
        assert.strictEqual(
          auditLogQuerySchema.safeParse(payload).success,
          true,
          `auditLogQuerySchema failed for ${JSON.stringify(payload)}`,
        );
        assert.strictEqual(
          auditSummaryQuerySchema.safeParse(payload).success,
          true,
          `auditSummaryQuerySchema failed for ${JSON.stringify(payload)}`,
        );
      }
    });

    it("should reject malformed dates, impossible calendar dates, and reversed date ranges across all 3 schemas", () => {
      const invalidDates = [
        "not-a-date",
        "12345",
        "31/02/2026",
        "2026-02-30",
        "2026-02-30T10:00:00Z",
      ];

      for (const badDate of invalidDates) {
        for (const schema of [
          exportAuditLogSchema,
          auditLogQuerySchema,
          auditSummaryQuerySchema,
        ]) {
          assert.strictEqual(
            schema.safeParse({ startDate: badDate }).success,
            false,
            `Expected startDate='${badDate}' to fail`,
          );
          assert.strictEqual(
            schema.safeParse({ endDate: badDate }).success,
            false,
            `Expected endDate='${badDate}' to fail`,
          );
        }
      }

      const reversedRanges = [
        { startDate: "2026-11-26", endDate: "2026-11-20" },
        { startDate: "26/11/2026", endDate: "20/11/2026" },
        {
          startDate: "2026-11-26T15:00:00Z",
          endDate: "2026-11-26T10:00:00Z",
        },
      ];

      for (const range of reversedRanges) {
        for (const schema of [
          exportAuditLogSchema,
          auditLogQuerySchema,
          auditSummaryQuerySchema,
        ]) {
          const parsed = schema.safeParse(range);
          assert.strictEqual(
            parsed.success,
            false,
            `Expected reversed range ${JSON.stringify(range)} to fail`,
          );
          if (!parsed.success) {
            assert.ok(
              parsed.error.issues.some(
                (i) =>
                  i.path.includes("endDate") &&
                  i.message.includes("endDate phải lớn hơn hoặc bằng startDate"),
              ),
            );
          }
        }
      }
    });
  });

  describe("3. AuditRepository & AuditService Unit Tests", () => {
    function createMockDb() {
      const capturedSqls: Array<{ sql: string; values: unknown[] }> = [];
      let findManyCalled = false;

      const db = {
        auditLog: {
          findMany: async () => {
            findManyCalled = true;
            return [];
          },
          count: async () => 0,
        },
        user: {
          findMany: async () => [],
        },
        $queryRaw: async (stringsOrSql: any, ...args: any[]) => {
          const sqlObj = Array.isArray(stringsOrSql)
            ? Prisma.sql(stringsOrSql as unknown as TemplateStringsArray, ...args)
            : stringsOrSql;
          const sqlText = String(sqlObj?.sql ?? sqlObj);
          const values = Array.isArray(sqlObj?.values) ? sqlObj.values : [];
          capturedSqls.push({ sql: sqlText, values });
          return sqlText.includes("COUNT(*)") ? [{ count: 0n }] : [];
        },
        $transaction: async (ops: any[]) => {
          const results: any[] = [];
          for (const op of ops) {
            results.push(await op);
          }
          return results;
        },
      } as any;

      return {
        db,
        getCapturedSqls: () => capturedSqls,
        wasFindManyCalled: () => findManyCalled,
      };
    }

    it("findAll should preserve Prisma findMany when status is omitted and use parameterized SQL when status is set", async () => {
      const noStatusMock = createMockDb();
      const noStatusRepo = new AuditRepository(noStatusMock.db);
      await noStatusRepo.findAll({ page: 1, limit: 20 });
      assert.strictEqual(noStatusMock.wasFindManyCalled(), true);
      assert.strictEqual(noStatusMock.getCapturedSqls().length, 0);

      for (const status of [AUDIT_LOG_STATUS.FAILED, AUDIT_LOG_STATUS.SUCCESS]) {
        const mock = createMockDb();
        const repo = new AuditRepository(mock.db);
        await repo.findAll({
          status,
          search: "LOGIN",
          startDate: "2026-11-26",
          endDate: "2026-11-26",
          page: 1,
          limit: 10,
        });

        assert.strictEqual(mock.wasFindManyCalled(), false);
        const sqls = mock.getCapturedSqls();
        assert.strictEqual(sqls.length, 2);

        for (const q of sqls) {
          assert.ok(q.sql.includes("COALESCE(("), `Missing COALESCE in ${q.sql}`);
          assert.ok(q.sql.includes("AT TIME ZONE 'UTC'"), `Missing UTC cast in ${q.sql}`);
          assert.ok(q.sql.includes("STRPOS(LOWER("), `Missing search filter in ${q.sql}`);
          if (status === AUDIT_LOG_STATUS.SUCCESS) {
            assert.ok(q.sql.includes("NOT (COALESCE(("), `Missing NOT in ${q.sql}`);
          } else {
            assert.ok(!q.sql.includes("NOT (COALESCE(("), `Unexpected NOT in ${q.sql}`);
          }
        }
      }
    });

    it("searchFts should apply status and UTC date filters in raw FTS SQL", async () => {
      const mock = createMockDb();
      const repo = new AuditRepository(mock.db);

      await repo.searchFts({
        search: "LOGIN",
        status: AUDIT_LOG_STATUS.FAILED,
        startDate: "2026-11-26",
        endDate: "2026-11-26",
        page: 1,
        limit: 20,
      });

      const sqls = mock.getCapturedSqls();
      assert.strictEqual(sqls.length, 2);
      for (const q of sqls) {
        assert.ok(q.sql.includes("to_tsquery('simple'"));
        assert.ok(q.sql.includes("COALESCE(("));
        assert.ok(q.sql.includes("AT TIME ZONE 'UTC'"));
      }
    });

    it("findForExport should preserve Prisma findMany when status is omitted and use parameterized SQL when status is set", async () => {
      const noStatusMock = createMockDb();
      const noStatusRepo = new AuditRepository(noStatusMock.db);
      await noStatusRepo.findForExport({ action: "CREATE_ROLE" });
      assert.strictEqual(noStatusMock.wasFindManyCalled(), true);

      const statusMock = createMockDb();
      const statusRepo = new AuditRepository(statusMock.db);
      await statusRepo.findForExport({ status: AUDIT_LOG_STATUS.SUCCESS }, 250);
      assert.strictEqual(statusMock.wasFindManyCalled(), false);
      const sqls = statusMock.getCapturedSqls();
      assert.strictEqual(sqls.length, 1);
      assert.ok(sqls[0].sql.includes("NOT (COALESCE(("));
      assert.ok(sqls[0].values.includes(250));
    });

    it("AuditService.exportLogs should pass status to findForExport and include Trạng thái column in CSV", async () => {
      let capturedQuery: any = null;
      const nowIso = new Date().toISOString();
      const mockRepo = {
        findForExport: async (dto: any) => {
          capturedQuery = dto;
          return [
            {
              id: "log-1",
              actorId: null,
              actor: null,
              action: "LOGIN_FAILED",
              status: AUDIT_LOG_STATUS.FAILED,
              targetType: "USER",
              targetId: "user-1",
              details: { errorMessage: "Sai mật khẩu" },
              ipAddress: "127.0.0.1",
              userAgent: "test-agent",
              createdAt: nowIso,
            },
          ];
        },
      } as unknown as AuditRepository;

      const service = new AuditService(mockRepo);
      const result = await service.exportLogs({
        format: "csv",
        status: AUDIT_LOG_STATUS.FAILED,
      });

      assert.strictEqual(capturedQuery.status, AUDIT_LOG_STATUS.FAILED);
      assert.strictEqual(result.format, "csv");
      assert.strictEqual(result.count, 1);
      const csv = result.data as string;
      const lines = csv.replace(/^\uFEFF/, "").split("\r\n");
      assert.strictEqual(lines.length, 2);
      assert.ok(lines[0].includes("Hành động,Trạng thái,Loại tài nguyên"));
      assert.ok(lines[1].includes('"LOGIN_FAILED","FAILED","USER"'));
    });
  });

  describe("4. OpenAPI Spec Assertions", () => {
    it("should document status query enum on /audit-logs and /audit-logs/export and mark /audit-logs/incident-reviews deprecated", () => {
      const paths = swaggerSpec.paths as Record<string, any>;

      for (const pathKey of ["/audit-logs", "/audit-logs/export"]) {
        const getOp = paths[pathKey]?.get;
        assert.ok(getOp, `Missing GET ${pathKey} in OpenAPI spec`);
        const statusParam = (getOp.parameters || []).find(
          (p: any) => p.name === "status" && p.in === "query",
        );
        assert.ok(statusParam, `Missing query param 'status' on ${pathKey}`);
        assert.deepStrictEqual(
          statusParam.schema?.enum,
          ["SUCCESS", "FAILED"],
        );
      }

      const incidentReviewsOp = paths["/audit-logs/incident-reviews"]?.get;
      assert.ok(
        incidentReviewsOp,
        "Missing GET /audit-logs/incident-reviews in OpenAPI spec",
      );
      assert.strictEqual(incidentReviewsOp.deprecated, true);
    });
  });

  describe("5. Live HTTP + PostgreSQL (ppe_identity_db) Integration Tests", () => {
    let dbAvailable = false;
    let server: http.Server | null = null;
    let baseUrl = "";
    let adminToken = "";
    let createdTempRoleId: string | null = null;
    const createdUserIds: string[] = [];
    const createdAuditLogIds: string[] = [];

    const suffix = crypto.randomBytes(4).toString("hex");
    const testTargetType = `IT_AUDIT_${suffix.toUpperCase()}`;
    const ftsToken = `auditflt${suffix}`;

    async function requestRaw(
      path: string,
      token: string | null = adminToken,
    ): Promise<{
      status: number;
      headers: Headers;
      text: string;
      body: any;
    }> {
      const headers: Record<string, string> = {};
      if (token) {
        headers.authorization = `Bearer ${token}`;
      }
      if (envConfig.gateway.internalSecret) {
        headers[GATEWAY_HEADERS.INTERNAL_SECRET] =
          envConfig.gateway.internalSecret;
      }
      const res = await fetch(`${baseUrl}${path}`, { method: "GET", headers });
      const text = await res.text();
      let body: any = null;
      const contentType = res.headers.get("content-type") || "";
      if (contentType.includes("application/json") && text) {
        body = JSON.parse(text);
      }
      return {
        status: res.status,
        headers: res.headers,
        text,
        body,
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

      const adminCaller = await prisma.user.create({
        data: {
          email: `it-audit-admin-${suffix}@smartppe.local`,
          fullName: `Admin Audit ${suffix}`,
          roleId: adminRole.id,
          isActive: true,
          deletedAt: null,
          siteIds: [],
        },
      });
      createdUserIds.push(adminCaller.id);

      adminToken = jwtKeyService.signAccessToken({
        id: adminCaller.id,
        email: adminCaller.email!,
        role: ROLES.ADMIN,
        roleId: adminRole.id,
        permissions: [PERMISSIONS.AUDIT_LOG_READ, PERMISSIONS.AUDIT_LOG_EXPORT],
        purpose: JWT_PURPOSE.ACCESS,
        mustChangePassword: false,
      });

      server = await new Promise<http.Server>((resolve) => {
        const s = app.listen(0, "127.0.0.1", () => resolve(s));
      });
      const addr = server.address() as AddressInfo;
      baseUrl = `http://127.0.0.1:${addr.port}`;

      // Seed 13 tagged audit_logs rows covering all SUCCESS and FAILED variants
      const baseTime = new Date("2026-11-26T05:00:00.000Z").getTime();
      const seedEntries: Array<{
        action: string;
        details: Prisma.InputJsonValue | typeof Prisma.DbNull;
        expectedStatus: "SUCCESS" | "FAILED";
        ipAddress: string;
      }> = [
        // 5 SUCCESS variants
        {
          action: AUDIT_ACTION.CREATE_ROLE,
          details: Prisma.DbNull,
          expectedStatus: "SUCCESS",
          ipAddress: ftsToken,
        },
        {
          action: AUDIT_ACTION.UPDATE_SYSTEM_CONFIG,
          details: { ok: true },
          expectedStatus: "SUCCESS",
          ipAddress: ftsToken,
        },
        {
          action: AUDIT_ACTION.CREATE_API_KEY,
          details: { error: false },
          expectedStatus: "SUCCESS",
          ipAddress: ftsToken,
        },
        {
          action: AUDIT_ACTION.TOGGLE_API_KEY,
          details: { error: null },
          expectedStatus: "SUCCESS",
          ipAddress: ftsToken,
        },
        {
          action: AUDIT_ACTION.UPDATE_ROLE,
          details: { error: "" },
          expectedStatus: "SUCCESS",
          ipAddress: ftsToken,
        },
        // 8 FAILED variants
        {
          action: AUDIT_ACTION.UPDATE_SYSTEM_CONFIG,
          details: { status: "FAILED" },
          expectedStatus: "FAILED",
          ipAddress: ftsToken,
        },
        {
          action: AUDIT_ACTION.UPDATE_SYSTEM_CONFIG,
          details: { status: " error " },
          expectedStatus: "FAILED",
          ipAddress: ftsToken,
        },
        {
          action: AUDIT_ACTION.TRIGGER_CRON_JOB,
          details: { success: false },
          expectedStatus: "FAILED",
          ipAddress: ftsToken,
        },
        {
          action: AUDIT_ACTION.TRIGGER_CRON_JOB,
          details: { errorMessage: "Boom" },
          expectedStatus: "FAILED",
          ipAddress: ftsToken,
        },
        {
          action: AUDIT_ACTION.VERIFY_2FA_LOGIN,
          details: { error: "Socket closed" },
          expectedStatus: "FAILED",
          ipAddress: ftsToken,
        },
        {
          action: AUDIT_ACTION.VERIFY_2FA_LOGIN,
          details: { error: { code: 500 } },
          expectedStatus: "FAILED",
          ipAddress: ftsToken,
        },
        {
          action: AUDIT_ACTION.ACCOUNT_LOCKED,
          details: Prisma.DbNull,
          expectedStatus: "FAILED",
          ipAddress: ftsToken,
        },
        {
          action: "LOGIN_FAILED",
          details: { attempts: 1 },
          expectedStatus: "FAILED",
          ipAddress: ftsToken,
        },
      ];

      for (let i = 0; i < seedEntries.length; i++) {
        const entry = seedEntries[i];
        const created = await prisma.auditLog.create({
          data: {
            actorId: adminCaller.id,
            action: entry.action,
            targetType: testTargetType,
            targetId: `target-${i + 1}`,
            details: entry.details,
            ipAddress: entry.ipAddress,
            userAgent: `it-audit-${entry.expectedStatus.toLowerCase()}`,
            createdAt: new Date(baseTime + i * 1000),
          },
        });
        createdAuditLogIds.push(created.id);
      }
    });

    after(async () => {
      try {
        if (createdAuditLogIds.length > 0 && dbAvailable) {
          await prisma.auditLog
            .deleteMany({ where: { id: { in: createdAuditLogIds } } })
            .catch(() => {});
        }
        if (createdUserIds.length > 0 && dbAvailable) {
          await prisma.user
            .deleteMany({ where: { id: { in: createdUserIds } } })
            .catch(() => {});
        }
        if (createdTempRoleId && dbAvailable) {
          await prisma.role
            .deleteMany({ where: { id: createdTempRoleId } })
            .catch(() => {});
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

    it("GET /api/v1/audit-logs?status=FAILED|SUCCESS should filter accurately and paginate", async (t) => {
      if (!dbAvailable) {
        t.skip("PostgreSQL ppe_identity_db is unavailable");
        return;
      }

      const failedRes = await requestRaw(
        `/api/v1/audit-logs?targetType=${testTargetType}&status=FAILED&limit=50`,
      );
      assert.strictEqual(failedRes.status, 200);
      assert.strictEqual(failedRes.body.success, true);
      assert.strictEqual(failedRes.body.meta?.total, 8);
      assert.strictEqual(failedRes.body.data.length, 8);
      for (const item of failedRes.body.data) {
        assert.strictEqual(item.status, AUDIT_LOG_STATUS.FAILED);
      }

      const successRes = await requestRaw(
        `/api/v1/audit-logs?targetType=${testTargetType}&status=SUCCESS&limit=50`,
      );
      assert.strictEqual(successRes.status, 200);
      assert.strictEqual(successRes.body.meta?.total, 5);
      assert.strictEqual(successRes.body.data.length, 5);
      for (const item of successRes.body.data) {
        assert.strictEqual(item.status, AUDIT_LOG_STATUS.SUCCESS);
      }

      // Page 2 with limit=2 on FAILED (8 total -> 4 pages, 2 items on page 2)
      const page2Res = await requestRaw(
        `/api/v1/audit-logs?targetType=${testTargetType}&status=FAILED&page=2&limit=2`,
      );
      assert.strictEqual(page2Res.status, 200);
      assert.strictEqual(page2Res.body.meta?.total, 8);
      assert.strictEqual(page2Res.body.meta?.page, 2);
      assert.strictEqual(page2Res.body.meta?.totalPages, 4);
      assert.strictEqual(page2Res.body.data.length, 2);
    });

    it("GET /api/v1/audit-logs?search=<token>&status=... should apply status in PostgreSQL FTS", async (t) => {
      if (!dbAvailable) {
        t.skip("PostgreSQL ppe_identity_db is unavailable");
        return;
      }

      const ftsFailed = await requestRaw(
        `/api/v1/audit-logs?search=${ftsToken}&status=FAILED&limit=50`,
      );
      assert.strictEqual(ftsFailed.status, 200);
      assert.strictEqual(ftsFailed.body.meta?.total, 8);
      assert.strictEqual(ftsFailed.body.data.length, 8);
      for (const item of ftsFailed.body.data) {
        assert.strictEqual(item.status, AUDIT_LOG_STATUS.FAILED);
      }

      const ftsSuccess = await requestRaw(
        `/api/v1/audit-logs?search=${ftsToken}&status=SUCCESS&limit=50`,
      );
      assert.strictEqual(ftsSuccess.status, 200);
      assert.strictEqual(ftsSuccess.body.meta?.total, 5);
      assert.strictEqual(ftsSuccess.body.data.length, 5);
      for (const item of ftsSuccess.body.data) {
        assert.strictEqual(item.status, AUDIT_LOG_STATUS.SUCCESS);
      }
    });

    it("GET /api/v1/audit-logs/export should filter by status in JSON and CSV", async (t) => {
      if (!dbAvailable) {
        t.skip("PostgreSQL ppe_identity_db is unavailable");
        return;
      }

      const jsonRes = await requestRaw(
        `/api/v1/audit-logs/export?format=json&targetType=${testTargetType}&status=FAILED`,
      );
      assert.strictEqual(jsonRes.status, 200);
      assert.strictEqual(jsonRes.body.success, true);
      assert.strictEqual(jsonRes.body.count, 8);
      assert.strictEqual(jsonRes.body.data.length, 8);
      for (const item of jsonRes.body.data) {
        assert.strictEqual(item.status, AUDIT_LOG_STATUS.FAILED);
      }

      const csvRes = await requestRaw(
        `/api/v1/audit-logs/export?format=csv&targetType=${testTargetType}&status=SUCCESS`,
      );
      assert.strictEqual(csvRes.status, 200);
      const lines = csvRes.text
        .replace(/^\uFEFF/, "")
        .trim()
        .split("\r\n");
      assert.strictEqual(lines.length, 6); // 1 header + 5 SUCCESS rows
      assert.ok(lines[0].includes("Trạng thái"));
      for (const rowLine of lines.slice(1)) {
        assert.ok(rowLine.includes('"SUCCESS"'));
        assert.ok(!rowLine.includes('"FAILED"'));
      }
    });

    it("GET /api/v1/audit-logs/export should reject invalid dates and reversed ranges with 422 VALIDATION_ERROR", async (t) => {
      if (!dbAvailable) {
        t.skip("PostgreSQL ppe_identity_db is unavailable");
        return;
      }

      const badUrls = [
        "/api/v1/audit-logs/export?startDate=2026-11-26&endDate=2026-11-20",
        "/api/v1/audit-logs/export?startDate=26/11/2026&endDate=20/11/2026",
        "/api/v1/audit-logs/export?startDate=invalid-date",
      ];

      for (const url of badUrls) {
        const res = await requestRaw(url);
        assert.strictEqual(res.status, 422, `Expected 422 for ${url}`);
        assert.strictEqual(res.body.code, ERROR_CODE.VALIDATION_ERROR);
      }
    });

    it("GET /api/v1/audit-logs/incident-reviews should return 200 with RFC 8594 deprecation headers", async (t) => {
      if (!dbAvailable) {
        t.skip("PostgreSQL ppe_identity_db is unavailable");
        return;
      }

      const res = await requestRaw("/api/v1/audit-logs/incident-reviews");
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.success, true);
      assert.strictEqual(res.headers.get("deprecation"), "true");
      assert.strictEqual(
        res.headers.get("x-deprecation-notice"),
        AUDIT_DEPRECATION_NOTICE,
      );
    });

    it("GET /api/v1/audit-logs/summary should return scope IDENTITY and accurate status counts", async (t) => {
      if (!dbAvailable) {
        t.skip("PostgreSQL ppe_identity_db is unavailable");
        return;
      }

      const res = await requestRaw(
        "/api/v1/audit-logs/summary?startDate=2026-11-26&endDate=2026-11-26",
      );
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.success, true);
      const data = res.body.data;
      assert.strictEqual(data.scope, AUDIT_SCOPE.IDENTITY);
      assert.ok(typeof data.totalLogs === "number" && data.totalLogs >= 13);
      assert.ok(typeof data.successCount === "number" && data.successCount >= 5);
      assert.ok(typeof data.failedCount === "number" && data.failedCount >= 8);
      assert.strictEqual(data.successCount + data.failedCount, data.totalLogs);
      assert.ok(typeof data.successRate === "number");
      assert.ok(typeof data.categoryCounts?.incidentReview === "number");
    });
  });
});
