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
import { findAllUserSchema } from "../src/modules/users/user.validation";
import { UserRepository } from "../src/modules/users/user.repository";
import { UserService } from "../src/modules/users/user.service";
import { permissionCacheService } from "../src/common/services/permission-cache.service";
import { ROLES } from "../src/common/constants/role.constant";
import { swaggerSpec } from "../src/config/swagger.config";

describe("Issue #4: GET /api/v1/users/summary & twoFactorEnabled / isLocked Filters", () => {
  const siteIdA = "018f2345-6789-7abc-def0-1234567890ab";
  const userId1 = "018f0000-0000-7000-8000-000000000001";
  const roleIdUser = "018f0000-0000-7000-8000-000000000011";
  const roleIdAdmin = "018f0000-0000-7000-8000-000000000012";

  beforeEach(() => {
    permissionCacheService.clear();
    (permissionCacheService as any).cache.set(roleIdUser, {
      permissions: new Set([PERMISSIONS.USER_READ]),
      expiresAt: Date.now() + 60_000,
    });
    (permissionCacheService as any).cache.set(roleIdAdmin, {
      permissions: new Set(["ADMIN_ALL"]),
      expiresAt: Date.now() + 60_000,
    });
  });

  describe("1. findAllUserSchema Validation", () => {
    it("should leave twoFactorEnabled and isLocked undefined for empty query", () => {
      const parsed = findAllUserSchema.parse({});
      assert.strictEqual(parsed.twoFactorEnabled, undefined);
      assert.strictEqual(parsed.isLocked, undefined);
      assert.strictEqual(parsed.page, 1);
      assert.strictEqual(parsed.limit, 20);
    });

    it("should parse twoFactorEnabled and isLocked string booleans along with combined filters", () => {
      const parsedTrue = findAllUserSchema.parse({
        twoFactorEnabled: "true",
        isLocked: "false",
        siteId: siteIdA,
        roleName: ROLES.SAFETY_OFFICER,
        search: "nguyen",
        page: "2",
        limit: "15",
      });
      assert.strictEqual(parsedTrue.twoFactorEnabled, true);
      assert.strictEqual(parsedTrue.isLocked, false);
      assert.strictEqual(parsedTrue.siteId, siteIdA);
      assert.strictEqual(parsedTrue.roleName, ROLES.SAFETY_OFFICER);
      assert.strictEqual(parsedTrue.search, "nguyen");
      assert.strictEqual(parsedTrue.page, 2);
      assert.strictEqual(parsedTrue.limit, 15);

      const parsedFalse = findAllUserSchema.parse({
        twoFactorEnabled: "false",
        isLocked: "true",
      });
      assert.strictEqual(parsedFalse.twoFactorEnabled, false);
      assert.strictEqual(parsedFalse.isLocked, true);
    });

    it("should reject invalid twoFactorEnabled and isLocked values", () => {
      for (const bad of ["yes", "1", "", "invalid"]) {
        assert.throws(() =>
          findAllUserSchema.parse({ twoFactorEnabled: bad }),
        );
        assert.throws(() => findAllUserSchema.parse({ isLocked: bad }));
      }
    });
  });

  describe("2. UserRepository.findAll Filtering", () => {
    function createMockDb(returnedRows: any[] = [], totalCount: number = 0) {
      let capturedFindManyArgs: any = null;
      let capturedCountArgs: any = null;

      const db = {
        user: {
          findMany: (args: any) => {
            capturedFindManyArgs = args;
            return { type: "findMany", args };
          },
          count: (args: any) => {
            capturedCountArgs = args;
            return { type: "count", args };
          },
        },
        $transaction: async (ops: any[]) => {
          assert.strictEqual(ops.length, 2);
          return [returnedRows, totalCount];
        },
      } as any;

      return {
        db,
        getCaptured: () => ({ capturedFindManyArgs, capturedCountArgs }),
      };
    }

    it("should filter by twoFactorEnabled identically in findMany and count", async () => {
      for (const flag of [true, false]) {
        const { db, getCaptured } = createMockDb([], 0);
        const repo = new UserRepository(db);

        await repo.findAll({ twoFactorEnabled: flag, page: 1, limit: 20 });
        const { capturedFindManyArgs, capturedCountArgs } = getCaptured();

        assert.deepStrictEqual(capturedFindManyArgs.where.AND, [
          { deletedAt: null },
          { twoFactorEnabled: flag },
        ]);
        assert.deepStrictEqual(
          capturedCountArgs.where.AND,
          capturedFindManyArgs.where.AND,
        );
      }
    });

    it("should filter isLocked=true using OR (!isActive or lockedUntil > now) with shared Date instance", async () => {
      const { db, getCaptured } = createMockDb([], 0);
      const repo = new UserRepository(db);

      await repo.findAll({ isLocked: true, page: 1, limit: 20 });
      const { capturedFindManyArgs, capturedCountArgs } = getCaptured();

      assert.strictEqual(capturedFindManyArgs.where.AND.length, 2);
      assert.deepStrictEqual(capturedFindManyArgs.where.AND[0], {
        deletedAt: null,
      });

      const lockCond = capturedFindManyArgs.where.AND[1];
      assert.ok(Array.isArray(lockCond.OR));
      assert.deepStrictEqual(lockCond.OR[0], { isActive: false });
      assert.ok(lockCond.OR[1].lockedUntil.gt instanceof Date);
      assert.deepStrictEqual(
        capturedCountArgs.where.AND,
        capturedFindManyArgs.where.AND,
      );
      assert.strictEqual(
        capturedCountArgs.where.AND[1].OR[1].lockedUntil.gt,
        lockCond.OR[1].lockedUntil.gt,
      );
    });

    it("should filter isLocked=false handling NULL lockedUntil explicitly", async () => {
      const { db, getCaptured } = createMockDb([], 0);
      const repo = new UserRepository(db);

      await repo.findAll({ isLocked: false, page: 1, limit: 20 });
      const { capturedFindManyArgs, capturedCountArgs } = getCaptured();

      assert.strictEqual(capturedFindManyArgs.where.AND.length, 2);
      const activeCond = capturedFindManyArgs.where.AND[1];
      assert.ok(Array.isArray(activeCond.AND));
      assert.deepStrictEqual(activeCond.AND[0], { isActive: true });
      assert.strictEqual(activeCond.AND[1].OR[0].lockedUntil, null);
      assert.ok(activeCond.AND[1].OR[1].lockedUntil.lte instanceof Date);
      assert.deepStrictEqual(
        capturedCountArgs.where.AND,
        capturedFindManyArgs.where.AND,
      );
    });

    it("should combine twoFactorEnabled, isLocked, siteId, and roleName cleanly", async () => {
      const { db, getCaptured } = createMockDb([], 0);
      const repo = new UserRepository(db);

      await repo.findAll({
        twoFactorEnabled: true,
        isLocked: true,
        siteId: siteIdA,
        roleName: ROLES.SAFETY_OFFICER,
        page: 1,
        limit: 10,
      });
      const { capturedFindManyArgs, capturedCountArgs } = getCaptured();

      assert.strictEqual(capturedFindManyArgs.where.AND.length, 5);
      assert.deepStrictEqual(capturedFindManyArgs.where.AND[0], {
        deletedAt: null,
      });
      assert.deepStrictEqual(capturedFindManyArgs.where.AND[1], {
        twoFactorEnabled: true,
      });
      assert.deepStrictEqual(capturedFindManyArgs.where.AND[3], {
        role: { name: ROLES.SAFETY_OFFICER },
      });
      assert.deepStrictEqual(capturedFindManyArgs.where.AND[4], {
        siteIds: { has: siteIdA },
      });
      assert.deepStrictEqual(
        capturedCountArgs.where.AND,
        capturedFindManyArgs.where.AND,
      );
    });
  });

  describe("3. UserRepository.searchFts Filtering", () => {
    function createMockFtsDb(rawRows: any[] = [], totalCount: number = 0) {
      const capturedSqls: Array<{ sql: string; values: unknown[] }> = [];

      const db = {
        $queryRaw: (stringsOrSql: any, ...args: any[]) => {
          const sqlObj = Array.isArray(stringsOrSql)
            ? Prisma.sql(stringsOrSql as unknown as TemplateStringsArray, ...args)
            : stringsOrSql;
          const entry = {
            sql: String(sqlObj?.sql ?? sqlObj),
            values: Array.isArray(sqlObj?.values) ? sqlObj.values : [],
          };
          capturedSqls.push(entry);
          return entry;
        },
        $transaction: async (ops: any[]) => {
          assert.strictEqual(ops.length, 2);
          return [rawRows, [{ count: BigInt(totalCount) }]];
        },
      } as any;

      return { db, capturedSqls };
    }

    function createRawUserRow(overrides: Record<string, any> = {}) {
      const now = new Date();
      return {
        id: userId1,
        email: "officer@ppe.vn",
        full_name: "Nguyen Van A",
        avatar_url: null,
        phone_number: "0901234567",
        role_id: roleIdUser,
        role_name: ROLES.SAFETY_OFFICER,
        site_ids: [siteIdA],
        is_active: true,
        two_factor_enabled: true,
        must_change_password: false,
        failed_login_attempts: 0,
        locked_until: null,
        deleted_at: null,
        created_at: now,
        updated_at: now,
        rank: 0.5,
        ...overrides,
      };
    }

    it("should bind u.two_factor_enabled in both data and count queries", async () => {
      const { db, capturedSqls } = createMockFtsDb([createRawUserRow()], 1);
      const repo = new UserRepository(db);

      await repo.searchFts({
        search: "Nguyen",
        twoFactorEnabled: true,
        page: 1,
        limit: 20,
      });

      assert.strictEqual(capturedSqls.length, 2);
      for (const q of capturedSqls) {
        assert.ok(q.sql.includes("u.two_factor_enabled ="));
        assert.ok(q.values.includes(true));
      }
    });

    it("should bind isLocked=true SQL condition in both data and count queries", async () => {
      const { db, capturedSqls } = createMockFtsDb([createRawUserRow()], 1);
      const repo = new UserRepository(db);

      await repo.searchFts({
        search: "Nguyen",
        isLocked: true,
        page: 1,
        limit: 20,
      });

      assert.strictEqual(capturedSqls.length, 2);
      for (const q of capturedSqls) {
        assert.ok(
          q.sql.includes(
            "(u.is_active = false OR (u.locked_until IS NOT NULL AND u.locked_until > (",
          ) && q.sql.includes("AT TIME ZONE 'UTC'"),
          `Unexpected SQL: ${q.sql}`,
        );
        assert.ok(q.values.some((v) => v instanceof Date));
      }
    });

    it("should bind isLocked=false SQL condition handling NULL locked_until in both queries", async () => {
      const { db, capturedSqls } = createMockFtsDb([createRawUserRow()], 1);
      const repo = new UserRepository(db);

      await repo.searchFts({
        search: "Nguyen",
        isLocked: false,
        page: 1,
        limit: 20,
      });

      assert.strictEqual(capturedSqls.length, 2);
      for (const q of capturedSqls) {
        assert.ok(
          q.sql.includes(
            "(u.is_active = true AND (u.locked_until IS NULL OR u.locked_until <= (",
          ) && q.sql.includes("AT TIME ZONE 'UTC'"),
          `Unexpected SQL: ${q.sql}`,
        );
        assert.ok(q.values.some((v) => v instanceof Date));
      }
    });

    it("should omit two_factor_enabled and locked_until filter clauses when omitted", async () => {
      const { db, capturedSqls } = createMockFtsDb([createRawUserRow()], 1);
      const repo = new UserRepository(db);

      await repo.searchFts({ search: "Nguyen", page: 1, limit: 20 });

      assert.strictEqual(capturedSqls.length, 2);
      for (const q of capturedSqls) {
        assert.ok(!q.sql.includes("u.two_factor_enabled ="));
        assert.ok(!q.sql.includes("u.locked_until IS NULL"));
        assert.ok(!q.sql.includes("u.locked_until IS NOT NULL"));
      }
    });
  });

  describe("4. UserRepository.getSummary Aggregation", () => {
    function createSummaryMockDb(kpiRows: any[], roleRows: any[]) {
      const capturedSqls: Array<{ sql: string; values: unknown[] }> = [];

      const db = {
        $queryRaw: (stringsOrSql: any, ...args: any[]) => {
          const sqlObj = Array.isArray(stringsOrSql)
            ? Prisma.sql(stringsOrSql as unknown as TemplateStringsArray, ...args)
            : stringsOrSql;
          const entry = {
            sql: String(sqlObj?.sql ?? sqlObj),
            values: Array.isArray(sqlObj?.values) ? sqlObj.values : [],
          };
          capturedSqls.push(entry);
          return entry;
        },
        $transaction: async (ops: any[]) => {
          assert.strictEqual(ops.length, 2);
          return [kpiRows, roleRows];
        },
      } as any;

      return { db, capturedSqls };
    }

    it("should run two parameterized SQL queries in $transaction and convert bigint counts", async () => {
      const { db, capturedSqls } = createSummaryMockDb(
        [
          {
            total: 12n,
            active: 9n,
            two_factor: 7n,
            locked: 3n,
          },
        ],
        [
          { role_name: ROLES.ADMIN, count: 2n },
          { role_name: ROLES.SAFETY_OFFICER, count: 10n },
        ],
      );
      const repo = new UserRepository(db);

      const summary = await repo.getSummary();

      assert.strictEqual(capturedSqls.length, 2);
      assert.ok(capturedSqls[0].sql.includes("deleted_at IS NULL"));
      assert.ok(capturedSqls[0].sql.includes("COUNT(*) FILTER"));
      assert.ok(capturedSqls[0].sql.includes("locked_until"));
      assert.strictEqual(capturedSqls[0].values.length, 2);
      assert.ok(
        capturedSqls[0].values[0] instanceof Date &&
          capturedSqls[0].values[0] === capturedSqls[0].values[1],
        "KPI active and locked filters must share the exact same Date cutoff",
      );
      assert.ok(capturedSqls[1].sql.includes("GROUP BY r.name"));
      assert.ok(capturedSqls[1].sql.includes("u.deleted_at IS NULL"));

      assert.deepStrictEqual(summary, {
        total: 12,
        active: 9,
        twoFactor: 7,
        locked: 3,
        byRole: {
          [ROLES.ADMIN]: 2,
          [ROLES.SAFETY_OFFICER]: 10,
        },
      });
    });

    it("should handle empty aggregate rows safely", async () => {
      const { db } = createSummaryMockDb([], []);
      const repo = new UserRepository(db);

      const summary = await repo.getSummary();
      assert.deepStrictEqual(summary, {
        total: 0,
        active: 0,
        twoFactor: 0,
        locked: 0,
        byRole: {},
      });
    });
  });

  describe("5. UserService Delegation & SEC-23 Redaction", () => {
    it("should delegate getSummary to repository.getSummary", async () => {
      const expected = {
        total: 5,
        active: 3,
        twoFactor: 2,
        locked: 2,
        byRole: { ADMIN: 1, USER: 4 },
      };
      const mockRepo = {
        getSummary: async () => expected,
      } as any;

      const service = new UserService(mockRepo, {} as any, {} as any);
      const res = await service.getSummary();
      assert.deepStrictEqual(res, expected);
    });

    it("should forward twoFactorEnabled & isLocked to findAll and searchFts while preserving SEC-23 redaction", async () => {
      let findAllQuery: any = null;
      let searchFtsQuery: any = null;
      const sampleUser = {
        id: userId1,
        email: "officer@ppe.vn",
        twoFactorEnabled: true,
        failedLoginAttempts: 5,
        lockedUntil: new Date(Date.now() + 60_000),
        mustChangePassword: true,
      };
      const mockRepo = {
        findAll: async (query: any) => {
          findAllQuery = query;
          return {
            data: [{ ...sampleUser }],
            meta: { total: 1, page: 1, limit: 20, totalPages: 1 },
          };
        },
        searchFts: async (query: any) => {
          searchFtsQuery = query;
          return {
            data: [{ ...sampleUser }],
            meta: { total: 1, page: 1, limit: 20, totalPages: 1 },
          };
        },
      } as any;

      const service = new UserService(mockRepo, {} as any, {} as any);

      const listRes = await service.findAll(
        { twoFactorEnabled: true, isLocked: true, page: 1, limit: 20 },
        { roleId: roleIdUser, role: ROLES.USER },
      );
      assert.strictEqual(findAllQuery.twoFactorEnabled, true);
      assert.strictEqual(findAllQuery.isLocked, true);
      assert.strictEqual(listRes.data[0].failedLoginAttempts, undefined);
      assert.strictEqual(listRes.data[0].lockedUntil, undefined);
      assert.strictEqual(listRes.data[0].mustChangePassword, undefined);

      const ftsRes = await service.findAll(
        {
          search: "officer",
          twoFactorEnabled: false,
          isLocked: false,
          page: 1,
          limit: 20,
        },
        { roleId: roleIdUser, role: ROLES.USER },
      );
      assert.strictEqual(searchFtsQuery.twoFactorEnabled, false);
      assert.strictEqual(searchFtsQuery.isLocked, false);
      assert.strictEqual(ftsRes.data[0].failedLoginAttempts, undefined);
      assert.strictEqual(ftsRes.data[0].lockedUntil, undefined);
      assert.strictEqual(ftsRes.data[0].mustChangePassword, undefined);
    });
  });

  describe("6. OpenAPI Specification", () => {
    it("should register GET /users/summary with BearerAuth and KPI response schema", () => {
      const summaryOp = swaggerSpec.paths?.["/users/summary"]?.get;
      assert.ok(summaryOp, "GET /users/summary must exist in OpenAPI spec");
      assert.ok(
        Array.isArray(summaryOp.security) &&
          summaryOp.security.some((s: any) => "BearerAuth" in s),
      );

      const dataProps =
        summaryOp.responses?.["200"]?.content?.["application/json"]?.schema
          ?.properties?.data?.properties;
      assert.ok(dataProps?.total);
      assert.ok(dataProps?.active);
      assert.ok(dataProps?.twoFactor);
      assert.ok(dataProps?.locked);
      assert.ok(dataProps?.byRole);
    });

    it("should expose twoFactorEnabled and isLocked query params on GET /users", () => {
      const getUsersOp = swaggerSpec.paths?.["/users"]?.get;
      assert.ok(getUsersOp, "GET /users must exist in OpenAPI spec");

      const params: any[] = getUsersOp.parameters || [];
      const twoFaParam = params.find((p) => p.name === "twoFactorEnabled");
      const lockedParam = params.find((p) => p.name === "isLocked");

      assert.ok(twoFaParam, "twoFactorEnabled query param must exist in OpenAPI");
      assert.strictEqual(twoFaParam.in, "query");
      assert.strictEqual(twoFaParam.required, false);

      assert.ok(lockedParam, "isLocked query param must exist in OpenAPI");
      assert.strictEqual(lockedParam.in, "query");
      assert.strictEqual(lockedParam.required, false);
    });
  });

  describe("7. Live HTTP + PostgreSQL (ppe_identity_db) Integration Tests", () => {
    let server: http.Server | null = null;
    let baseUrl = "";
    let dbAvailable = false;
    let adminToken = "";
    let noPermToken = "";
    let createdTempRoleId: string | null = null;
    let memberRoleName = "";
    const createdUserIds: string[] = [];
    const liveSiteId = crypto.randomUUID();
    const searchToken = `summaryflt${crypto.randomBytes(4).toString("hex")}`;

    let baselineSummary: {
      total: number;
      active: number;
      twoFactor: number;
      locked: number;
      byRole: Record<string, number>;
    };

    let u1Active2FAId = "";
    let u2ExpiredLockId = "";
    let u3TempLocked2FAId = "";
    let u4InactiveId = "";
    let u5InactiveTempLockedId = "";
    let u6DeletedId = "";

    async function requestJson(path: string, token: string | null = adminToken) {
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

      const memberRole =
        (await prisma.role.findFirst({
          where: { name: { in: [ROLES.SAFETY_OFFICER, ROLES.USER] } },
        })) || adminRole;
      memberRoleName = memberRole.name;

      const suffix = crypto.randomBytes(4).toString("hex");
      const adminCaller = await prisma.user.create({
        data: {
          email: `it-sum-admin-${suffix}@smartppe.local`,
          fullName: `Admin Summary ${suffix}`,
          roleId: adminRole.id,
          isActive: true,
          deletedAt: null,
          siteIds: [],
        },
      });
      createdUserIds.push(adminCaller.id);

      const noPermUser = await prisma.user.create({
        data: {
          email: `it-sum-noperm-${suffix}@smartppe.local`,
          fullName: `NoPerm Summary ${suffix}`,
          roleId: memberRole.id,
          isActive: true,
          deletedAt: null,
          siteIds: [],
        },
      });
      createdUserIds.push(noPermUser.id);

      adminToken = jwtKeyService.signAccessToken({
        id: adminCaller.id,
        email: adminCaller.email!,
        role: ROLES.ADMIN,
        roleId: adminRole.id,
        permissions: [PERMISSIONS.USER_READ],
        purpose: JWT_PURPOSE.ACCESS,
        mustChangePassword: false,
      });

      noPermToken = jwtKeyService.signAccessToken({
        id: noPermUser.id,
        email: noPermUser.email!,
        role: ROLES.USER,
        roleId: memberRole.id,
        permissions: [],
        purpose: JWT_PURPOSE.ACCESS,
        mustChangePassword: false,
      });

      server = await new Promise<http.Server>((resolve) => {
        const s = app.listen(0, "127.0.0.1", () => resolve(s));
      });
      const addr = server.address() as AddressInfo;
      baseUrl = `http://127.0.0.1:${addr.port}`;

      const baselineRes = await requestJson("/api/v1/users/summary");
      assert.strictEqual(baselineRes.status, 200);
      baselineSummary = baselineRes.body.data;

      const pastDate = new Date(Date.now() - 60 * 60 * 1000);
      const futureDate = new Date(Date.now() + 60 * 60 * 1000);

      const u1 = await prisma.user.create({
        data: {
          email: `it-sum-1-${suffix}@smartppe.local`,
          fullName: `Alpha ${searchToken} Active2FA`,
          roleId: memberRole.id,
          isActive: true,
          twoFactorEnabled: true,
          lockedUntil: null,
          deletedAt: null,
          siteIds: [liveSiteId],
        },
      });
      u1Active2FAId = u1.id;
      createdUserIds.push(u1.id);

      const u2 = await prisma.user.create({
        data: {
          email: `it-sum-2-${suffix}@smartppe.local`,
          fullName: `Beta ${searchToken} ExpiredLock`,
          roleId: memberRole.id,
          isActive: true,
          twoFactorEnabled: false,
          lockedUntil: pastDate,
          deletedAt: null,
          siteIds: [liveSiteId],
        },
      });
      u2ExpiredLockId = u2.id;
      createdUserIds.push(u2.id);

      const u3 = await prisma.user.create({
        data: {
          email: `it-sum-3-${suffix}@smartppe.local`,
          fullName: `Gamma ${searchToken} TempLocked2FA`,
          roleId: memberRole.id,
          isActive: true,
          twoFactorEnabled: true,
          lockedUntil: futureDate,
          deletedAt: null,
          siteIds: [liveSiteId],
        },
      });
      u3TempLocked2FAId = u3.id;
      createdUserIds.push(u3.id);

      const u4 = await prisma.user.create({
        data: {
          email: `it-sum-4-${suffix}@smartppe.local`,
          fullName: `Delta ${searchToken} Inactive`,
          roleId: memberRole.id,
          isActive: false,
          twoFactorEnabled: false,
          lockedUntil: null,
          deletedAt: null,
          siteIds: [liveSiteId],
        },
      });
      u4InactiveId = u4.id;
      createdUserIds.push(u4.id);

      const u5 = await prisma.user.create({
        data: {
          email: `it-sum-5-${suffix}@smartppe.local`,
          fullName: `Epsilon ${searchToken} InactiveTempLocked`,
          roleId: memberRole.id,
          isActive: false,
          twoFactorEnabled: false,
          lockedUntil: futureDate,
          deletedAt: null,
          siteIds: [liveSiteId],
        },
      });
      u5InactiveTempLockedId = u5.id;
      createdUserIds.push(u5.id);

      const u6 = await prisma.user.create({
        data: {
          email: `it-sum-6-${suffix}@smartppe.local`,
          fullName: `Zeta ${searchToken} Deleted`,
          roleId: memberRole.id,
          isActive: false,
          twoFactorEnabled: true,
          lockedUntil: futureDate,
          deletedAt: new Date(),
          siteIds: [liveSiteId],
        },
      });
      u6DeletedId = u6.id;
      createdUserIds.push(u6.id);
    });

    after(async () => {
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
      permissionCacheService.clear();
      if (server) {
        await new Promise<void>((resolve) => {
          server!.close(() => resolve());
        });
      }
      await prisma.$disconnect().catch(() => {});
    });

    it("GET /api/v1/users/summary should return accurate KPI deltas and role breakdown", async (t) => {
      if (!dbAvailable) {
        t.skip("PostgreSQL ppe_identity_db is unavailable");
        return;
      }

      const res = await requestJson("/api/v1/users/summary");
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.success, true);

      const data = res.body.data;
      assert.strictEqual(data.total, baselineSummary.total + 5);
      assert.strictEqual(data.active, baselineSummary.active + 2);
      assert.strictEqual(data.twoFactor, baselineSummary.twoFactor + 2);
      assert.strictEqual(data.locked, baselineSummary.locked + 3);
      assert.strictEqual(data.active + data.locked, data.total);
      assert.strictEqual(
        data.byRole[memberRoleName],
        (baselineSummary.byRole[memberRoleName] ?? 0) + 5,
      );
    });

    it("GET /api/v1/users/summary should enforce auth (401) and USER_READ permission (403)", async (t) => {
      if (!dbAvailable) {
        t.skip("PostgreSQL ppe_identity_db is unavailable");
        return;
      }

      const unauthRes = await requestJson("/api/v1/users/summary", null);
      assert.strictEqual(unauthRes.status, 401);

      const forbiddenRes = await requestJson(
        "/api/v1/users/summary",
        noPermToken,
      );
      assert.strictEqual(forbiddenRes.status, 403);
    });

    it("GET /api/v1/users?siteId=...&twoFactorEnabled=true|false should filter accurately", async (t) => {
      if (!dbAvailable) {
        t.skip("PostgreSQL ppe_identity_db is unavailable");
        return;
      }

      const enabledRes = await requestJson(
        `/api/v1/users?siteId=${liveSiteId}&twoFactorEnabled=true`,
      );
      assert.strictEqual(enabledRes.status, 200);
      assert.strictEqual(enabledRes.body.meta?.total, 2);
      assert.deepStrictEqual(
        (enabledRes.body.data as any[]).map((u) => u.id).sort(),
        [u1Active2FAId, u3TempLocked2FAId].sort(),
      );

      const disabledRes = await requestJson(
        `/api/v1/users?siteId=${liveSiteId}&twoFactorEnabled=false`,
      );
      assert.strictEqual(disabledRes.status, 200);
      assert.strictEqual(disabledRes.body.meta?.total, 3);
      assert.deepStrictEqual(
        (disabledRes.body.data as any[]).map((u) => u.id).sort(),
        [u2ExpiredLockId, u4InactiveId, u5InactiveTempLockedId].sort(),
      );
    });

    it("GET /api/v1/users?siteId=...&isLocked=true|false should filter accurately and paginate", async (t) => {
      if (!dbAvailable) {
        t.skip("PostgreSQL ppe_identity_db is unavailable");
        return;
      }

      const lockedRes = await requestJson(
        `/api/v1/users?siteId=${liveSiteId}&isLocked=true`,
      );
      assert.strictEqual(lockedRes.status, 200);
      assert.strictEqual(lockedRes.body.meta?.total, 3);
      assert.deepStrictEqual(
        (lockedRes.body.data as any[]).map((u) => u.id).sort(),
        [u3TempLocked2FAId, u4InactiveId, u5InactiveTempLockedId].sort(),
      );
      assert.ok(
        !(lockedRes.body.data as any[]).some((u) => u.id === u6DeletedId),
      );

      const unlockedRes = await requestJson(
        `/api/v1/users?siteId=${liveSiteId}&isLocked=false`,
      );
      assert.strictEqual(unlockedRes.status, 200);
      assert.strictEqual(unlockedRes.body.meta?.total, 2);
      assert.deepStrictEqual(
        (unlockedRes.body.data as any[]).map((u) => u.id).sort(),
        [u1Active2FAId, u2ExpiredLockId].sort(),
      );

      const page1 = await requestJson(
        `/api/v1/users?siteId=${liveSiteId}&isLocked=true&page=1&limit=2`,
      );
      assert.strictEqual(page1.status, 200);
      assert.deepStrictEqual(page1.body.meta, {
        total: 3,
        page: 1,
        limit: 2,
        totalPages: 2,
      });
      assert.strictEqual(page1.body.data.length, 2);

      const page2 = await requestJson(
        `/api/v1/users?siteId=${liveSiteId}&isLocked=true&page=2&limit=2`,
      );
      assert.strictEqual(page2.status, 200);
      assert.strictEqual(page2.body.data.length, 1);
    });

    it("GET /api/v1/users?search=<token> should apply twoFactorEnabled and isLocked in live PostgreSQL FTS", async (t) => {
      if (!dbAvailable) {
        t.skip("PostgreSQL ppe_identity_db is unavailable");
        return;
      }

      const twoFaFts = await requestJson(
        `/api/v1/users?search=${searchToken}&twoFactorEnabled=true`,
      );
      assert.strictEqual(twoFaFts.status, 200);
      assert.strictEqual(twoFaFts.body.meta?.total, 2);
      assert.deepStrictEqual(
        (twoFaFts.body.data as any[]).map((u) => u.id).sort(),
        [u1Active2FAId, u3TempLocked2FAId].sort(),
      );

      const lockedFts = await requestJson(
        `/api/v1/users?search=${searchToken}&isLocked=true`,
      );
      assert.strictEqual(lockedFts.status, 200);
      assert.strictEqual(lockedFts.body.meta?.total, 3);
      assert.deepStrictEqual(
        (lockedFts.body.data as any[]).map((u) => u.id).sort(),
        [u3TempLocked2FAId, u4InactiveId, u5InactiveTempLockedId].sort(),
      );

      const unlockedFts = await requestJson(
        `/api/v1/users?search=${searchToken}&isLocked=false`,
      );
      assert.strictEqual(unlockedFts.status, 200);
      assert.strictEqual(unlockedFts.body.meta?.total, 2);
      assert.deepStrictEqual(
        (unlockedFts.body.data as any[]).map((u) => u.id).sort(),
        [u1Active2FAId, u2ExpiredLockId].sort(),
      );
    });

    it("GET /api/v1/users with invalid twoFactorEnabled or isLocked should return 422 VALIDATION_ERROR", async (t) => {
      if (!dbAvailable) {
        t.skip("PostgreSQL ppe_identity_db is unavailable");
        return;
      }

      const badTwoFa = await requestJson(
        "/api/v1/users?twoFactorEnabled=invalid",
      );
      assert.strictEqual(badTwoFa.status, 422);
      assert.strictEqual(badTwoFa.body.code, ERROR_CODE.VALIDATION_ERROR);

      const badLocked = await requestJson("/api/v1/users?isLocked=invalid");
      assert.strictEqual(badLocked.status, 422);
      assert.strictEqual(badLocked.body.code, ERROR_CODE.VALIDATION_ERROR);
    });
  });
});
