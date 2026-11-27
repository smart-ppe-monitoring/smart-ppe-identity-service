import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
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
  DEFAULT_MAINTENANCE_CONFIG,
  MAINTENANCE_STATUS,
} from "../src/common/constants/maintenance.constant";
import {
  isIpInWhitelist,
  isIpv6InCidr,
  isValidIpOrCidr,
} from "../src/common/helpers/ip.helper";
import {
  enableMaintenanceSchema,
  updateMaintenanceSchema,
} from "../src/modules/maintenance/maintenance.validation";
import { MaintenanceService } from "../src/modules/maintenance/maintenance.service";
import { sseManagerService } from "../src/common/services/sse-manager.service";
import { maintenanceCacheService } from "../src/common/services/maintenance-cache.service";
import { permissionCacheService } from "../src/common/services/permission-cache.service";
import { jwtKeyService } from "../src/common/services/jwt-key.service";
import { AppError } from "../src/common/errors/app-error";
import { ERROR_CODE } from "../src/common/errors/error-code";

describe("Issue #11: Maintenance IP/CIDR Validation, Admin Anti-Lockout & Timestamp Consistency", () => {
  describe("1. IP/CIDR Format Validation & IPv6 CIDR Matching", () => {
    it("isValidIpOrCidr accepts valid IPv4, IPv6, and CIDR ranges", () => {
      for (const valid of [
        "127.0.0.1",
        "192.168.1.0/24",
        "10.0.0.0/8",
        "0.0.0.0/0",
        "::1",
        "fe80::1",
        "2001:db8::/32",
        "fe80::/10",
        "::/0",
        " ::1 ",
      ]) {
        assert.equal(
          isValidIpOrCidr(valid),
          true,
          `Expected '${valid}' to be valid`,
        );
      }
    });

    it("isValidIpOrCidr rejects malformed IPs and out-of-range CIDR prefixes", () => {
      for (const invalid of [
        "",
        "   ",
        "not-an-ip",
        "256.1.1.1",
        "192.168.1.1/33",
        "192.168.1.1/-1",
        "192.168.1.1/abc",
        "192.168.1.1/",
        "/24",
        "192.168.1.1/24/1",
        "2001:db8::/129",
        "2001:db8::/abc",
        "gggg::1",
      ]) {
        assert.equal(
          isValidIpOrCidr(invalid),
          false,
          `Expected '${invalid}' to be invalid`,
        );
      }
    });

    it("isIpv6InCidr & isIpInWhitelist match IPv6 CIDR subnets accurately", () => {
      assert.equal(isIpv6InCidr("2001:db8:abcd::1", "2001:db8::/32"), true);
      assert.equal(isIpv6InCidr("2001:db9::1", "2001:db8::/32"), false);
      assert.equal(
        isIpInWhitelist("2001:db8:1234::5", ["2001:db8::/32"]),
        true,
      );
      assert.equal(
        isIpInWhitelist("2001:db9::5", ["2001:db8::/32"]),
        false,
      );
    });
  });

  describe("2. Zod Validation for bypassIps & Anti-Lockout", () => {
    it("rejects invalid bypassIps and accepts valid IPv4/IPv6/CIDR in both schemas", () => {
      for (const schema of [enableMaintenanceSchema, updateMaintenanceSchema]) {
        const bad = schema.safeParse({
          bypassIps: ["192.168.1.10", "invalid-cidr/24"],
        });
        assert.equal(bad.success, false);

        const badPrefix = schema.safeParse({
          bypassIps: ["10.0.0.0/33"],
        });
        assert.equal(badPrefix.success, false);

        const good = schema.safeParse({
          bypassIps: ["10.0.0.0/8", "2001:db8::/32", "127.0.0.1"],
        });
        assert.equal(good.success, true);
      }
    });

    it("rejects clearing both bypassRoles and bypassPermissions in single request and allows keeping at least one admin key", () => {
      for (const schema of [enableMaintenanceSchema, updateMaintenanceSchema]) {
        const lockout = schema.safeParse({
          bypassRoles: [],
          bypassPermissions: [],
        });
        assert.equal(lockout.success, false);

        const nonAdminOnly = schema.safeParse({
          bypassRoles: [ROLES.OPERATOR],
          bypassPermissions: [PERMISSIONS.USER_READ],
        });
        assert.equal(nonAdminOnly.success, false);

        const keepAdminRole = schema.safeParse({
          bypassRoles: [ROLES.ADMIN],
          bypassPermissions: [],
        });
        assert.equal(keepAdminRole.success, true);

        const keepManagePerm = schema.safeParse({
          bypassRoles: [],
          bypassPermissions: [PERMISSIONS.MAINTENANCE_MANAGE],
        });
        assert.equal(keepManagePerm.success, true);
      }
    });

    it("OpenAPI swaggerSpec still compiles Maintenance schemas cleanly", () => {
      const schemas = swaggerSpec.components?.schemas as Record<string, any>;
      assert.ok(schemas?.EnableMaintenanceRequest);
      assert.ok(schemas?.UpdateMaintenanceRequest);
    });
  });

  describe("3. MaintenanceService Anti-Lockout, Stale estimatedEndAt & DB/SSE Consistency", () => {
    function createMockRepo(initialOverrides: Record<string, unknown> = {}) {
      let currentConfig: any = {
        id: "maint-cfg-1",
        key: "DEFAULT",
        enabled: false,
        status: MAINTENANCE_STATUS.ONLINE,
        title: DEFAULT_MAINTENANCE_CONFIG.title,
        message: DEFAULT_MAINTENANCE_CONFIG.message,
        startAt: null,
        estimatedEndAt: null,
        bypassPermissions: [...DEFAULT_MAINTENANCE_CONFIG.bypassPermissions],
        bypassRoles: [...DEFAULT_MAINTENANCE_CONFIG.bypassRoles],
        bypassIps: [],
        metadata: null,
        createdAt: new Date(),
        updatedAt: new Date(),
        ...initialOverrides,
      };
      const auditLogs: any[] = [];

      const repo = {
        getOrCreateDefaultConfig: async () => ({ ...currentConfig }),
        updateConfig: async (_key: string, data: Record<string, unknown>) => {
          currentConfig = {
            ...currentConfig,
            ...data,
            updatedAt: new Date(),
          };
          return { ...currentConfig };
        },
        createAuditLog: async (entry: any) => {
          auditLogs.push(entry);
        },
      };

      const cache = { invalidate: () => {} };
      return {
        repo,
        cache,
        getCurrent: () => currentConfig,
        auditLogs,
      };
    }

    it("enforces two-step Admin Anti-Lockout across sequential updates", async () => {
      const { repo, cache } = createMockRepo();
      const service = new MaintenanceService(repo as any, cache as any);

      // Step 1: remove ADMIN role while MAINTENANCE_MANAGE permission still remains -> allowed
      const step1 = await service.updateConfig({ bypassRoles: [] });
      assert.deepEqual(step1.bypassRoles, []);

      // Step 2: now attempt to also remove MAINTENANCE_MANAGE permission -> blocked (400 VALIDATION_ERROR)
      await assert.rejects(
        () =>
          service.updateConfig({
            bypassPermissions: [PERMISSIONS.MAINTENANCE_BYPASS],
          }),
        (err: AppError) =>
          err.statusCode === 400 && err.code === ERROR_CODE.VALIDATION_ERROR,
      );

      // Enable with empty bypassRoles when previousConfig permissions do not include MAINTENANCE_MANAGE -> blocked
      await assert.rejects(
        () =>
          service.enableMaintenance({
            bypassRoles: [],
            bypassPermissions: [PERMISSIONS.USER_READ],
          }),
        (err: AppError) =>
          err.statusCode === 400 && err.code === ERROR_CODE.VALIDATION_ERROR,
      );
    });

    it("enableMaintenance discards stale previous estimatedEndAt <= startAt and keeps future estimatedEndAt > startAt", async () => {
      // Case A: stale past estimatedEndAt
      const pastEnd = new Date(Date.now() - 60 * 60 * 1000);
      const mockA = createMockRepo({ estimatedEndAt: pastEnd });
      const serviceA = new MaintenanceService(
        mockA.repo as any,
        mockA.cache as any,
      );

      const enabledA = await serviceA.enableMaintenance({});
      assert.ok(enabledA.startAt instanceof Date);
      assert.equal(enabledA.estimatedEndAt, null);

      // Case B: stale equal estimatedEndAt === explicit startAt
      const exactStart = new Date(Date.now() + 60_000);
      const mockB = createMockRepo({ estimatedEndAt: exactStart });
      const serviceB = new MaintenanceService(
        mockB.repo as any,
        mockB.cache as any,
      );
      const enabledB = await serviceB.enableMaintenance({
        startAt: exactStart.toISOString(),
      });
      assert.equal(enabledB.estimatedEndAt, null);

      // Case C: valid future estimatedEndAt > startAt IS preserved if omitted
      const futureEnd = new Date(Date.now() + 2 * 60 * 60 * 1000);
      const mockC = createMockRepo({ estimatedEndAt: futureEnd });
      const serviceC = new MaintenanceService(
        mockC.repo as any,
        mockC.cache as any,
      );
      const enabledC = await serviceC.enableMaintenance({});
      assert.equal(
        enabledC.estimatedEndAt?.toISOString(),
        futureEnd.toISOString(),
      );

      // Case D: explicit invalid estimatedEndAt <= startAt throws 400
      await assert.rejects(
        () =>
          serviceC.enableMaintenance({
            startAt: futureEnd.toISOString(),
            estimatedEndAt: futureEnd.toISOString(),
          }),
        (err: AppError) =>
          err.statusCode === 400 && err.code === ERROR_CODE.VALIDATION_ERROR,
      );
    });

    it("disableMaintenance and updateConfig({ enabled: false }) clear startAt & estimatedEndAt in DB and SSE", async () => {
      const startAt = new Date(Date.now() - 10 * 60 * 1000);
      const estimatedEndAt = new Date(Date.now() + 50 * 60 * 1000);
      const mock = createMockRepo({
        enabled: true,
        status: MAINTENANCE_STATUS.MAINTENANCE,
        startAt,
        estimatedEndAt,
      });
      const service = new MaintenanceService(
        mock.repo as any,
        mock.cache as any,
      );

      const events: any[] = [];
      const originalBroadcast = sseManagerService.broadcast.bind(
        sseManagerService,
      );
      (sseManagerService as any).broadcast = (evt: any) => {
        events.push(evt);
      };

      try {
        const disabled = await service.disableMaintenance({
          actorId: "admin-1",
        });
        assert.equal(disabled.enabled, false);
        assert.equal(disabled.status, MAINTENANCE_STATUS.ONLINE);
        assert.equal(disabled.startAt, null);
        assert.equal(disabled.estimatedEndAt, null);

        assert.equal(events.length, 1);
        assert.equal(events[0].type, "system:maintenance");
        assert.equal(events[0].data.enabled, false);
        assert.equal(events[0].data.status, MAINTENANCE_STATUS.ONLINE);
        assert.equal(events[0].data.startAt, null);
        assert.equal(events[0].data.estimatedEndAt, null);

        // Also test updateConfig({ status: ONLINE }) clears timestamps when turning off
        await service.enableMaintenance({
          startAt: new Date(Date.now() - 5000).toISOString(),
          estimatedEndAt: new Date(Date.now() + 3600_000).toISOString(),
        });
        const turnedOff = await service.updateConfig({
          status: MAINTENANCE_STATUS.ONLINE,
        });
        assert.equal(turnedOff.enabled, false);
        assert.equal(turnedOff.startAt, null);
        assert.equal(turnedOff.estimatedEndAt, null);
      } finally {
        (sseManagerService as any).broadcast = originalBroadcast;
      }
    });
  });

  describe("4. Live HTTP + PostgreSQL (ppe_identity_db) Integration Tests", () => {
    let dbAvailable = false;
    let server: http.Server | null = null;
    let baseUrl = "";
    let adminToken = "";
    let adminUserId = "";
    let createdTempRoleId: string | null = null;
    const createdUserIds: string[] = [];
    const testStartTime = new Date();
    let originalConfigRow: any = null;
    let hadOriginalConfigRow = false;

    const suffix = crypto.randomBytes(4).toString("hex");

    async function requestApi(
      method: "GET" | "POST" | "PUT",
      path: string,
      body?: unknown,
    ) {
      const headers: Record<string, string> = {
        authorization: `Bearer ${adminToken}`,
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
      maintenanceCacheService.clear();

      originalConfigRow = await prisma.maintenanceConfig.findUnique({
        where: { key: "DEFAULT" },
      });
      hadOriginalConfigRow = Boolean(originalConfigRow);

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
          email: `it-issue11-admin-${suffix}@smartppe.local`,
          fullName: `Issue11 Admin ${suffix}`,
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
          PERMISSIONS.MAINTENANCE_READ,
          PERMISSIONS.MAINTENANCE_MANAGE,
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
          if (hadOriginalConfigRow && originalConfigRow) {
            await prisma.maintenanceConfig
              .upsert({
                where: { key: "DEFAULT" },
                update: {
                  enabled: originalConfigRow.enabled,
                  status: originalConfigRow.status,
                  title: originalConfigRow.title,
                  message: originalConfigRow.message,
                  startAt: originalConfigRow.startAt,
                  estimatedEndAt: originalConfigRow.estimatedEndAt,
                  bypassPermissions: originalConfigRow.bypassPermissions,
                  bypassRoles: originalConfigRow.bypassRoles,
                  bypassIps: originalConfigRow.bypassIps,
                },
                create: {
                  key: "DEFAULT",
                  enabled: originalConfigRow.enabled,
                  status: originalConfigRow.status,
                  title: originalConfigRow.title,
                  message: originalConfigRow.message,
                  startAt: originalConfigRow.startAt,
                  estimatedEndAt: originalConfigRow.estimatedEndAt,
                  bypassPermissions: originalConfigRow.bypassPermissions,
                  bypassRoles: originalConfigRow.bypassRoles,
                  bypassIps: originalConfigRow.bypassIps,
                },
              })
              .catch(() => {});
          } else {
            await prisma.maintenanceConfig
              .deleteMany({ where: { key: "DEFAULT" } })
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
        maintenanceCacheService.clear();
        permissionCacheService.clear();
        if (server) {
          await new Promise<void>((resolve) => {
            server!.close(() => resolve());
          });
        }
        await prisma.$disconnect().catch(() => {});
      }
    });

    it("rejects invalid bypassIps (422) and two-step lockout (400), drops stale estimatedEndAt on enable, and syncs null timestamps on disable", async (t) => {
      if (!dbAvailable) {
        t.skip("PostgreSQL ppe_identity_db is unavailable");
        return;
      }

      // 1. Invalid CIDR in PUT /api/v1/maintenance/config returns 422 VALIDATION_ERROR
      const badIpRes = await requestApi("PUT", "/api/v1/maintenance/config", {
        bypassIps: ["192.168.1.999"],
      });
      assert.strictEqual(badIpRes.status, 422);
      assert.strictEqual(badIpRes.body.code, ERROR_CODE.VALIDATION_ERROR);

      // 2. Single-step lockout returns 422 VALIDATION_ERROR
      const singleLockoutRes = await requestApi(
        "PUT",
        "/api/v1/maintenance/config",
        {
          bypassRoles: [],
          bypassPermissions: [],
        },
      );
      assert.strictEqual(singleLockoutRes.status, 422);

      // 3. Valid IPv4 + IPv6 CIDR succeeds and two-step lockout fails at service layer (400)
      const validCfgRes = await requestApi(
        "PUT",
        "/api/v1/maintenance/config",
        {
          bypassRoles: [],
          bypassPermissions: [PERMISSIONS.MAINTENANCE_MANAGE],
          bypassIps: ["10.10.0.0/16", "2001:db8::/32"],
        },
      );
      assert.strictEqual(validCfgRes.status, 200);
      assert.deepEqual(validCfgRes.body.data.bypassIps, [
        "10.10.0.0/16",
        "2001:db8::/32",
      ]);

      const twoStepLockoutRes = await requestApi(
        "PUT",
        "/api/v1/maintenance/config",
        {
          bypassPermissions: [],
        },
      );
      assert.strictEqual(twoStepLockoutRes.status, 400);
      assert.strictEqual(
        twoStepLockoutRes.body.code,
        ERROR_CODE.VALIDATION_ERROR,
      );

      // Restore admin role bypass for clean state before enable/disable lifecycle check
      await requestApi("PUT", "/api/v1/maintenance/config", {
        bypassRoles: [...DEFAULT_MAINTENANCE_CONFIG.bypassRoles],
        bypassPermissions: [...DEFAULT_MAINTENANCE_CONFIG.bypassPermissions],
      });

      // 4. Plant stale estimatedEndAt in DB and call POST /api/v1/maintenance/enable without estimatedEndAt
      const stalePast = new Date(Date.now() - 2 * 60 * 60 * 1000);
      await prisma.maintenanceConfig.upsert({
        where: { key: "DEFAULT" },
        update: { estimatedEndAt: stalePast },
        create: {
          key: "DEFAULT",
          enabled: false,
          status: MAINTENANCE_STATUS.ONLINE,
          title: DEFAULT_MAINTENANCE_CONFIG.title,
          message: DEFAULT_MAINTENANCE_CONFIG.message,
          estimatedEndAt: stalePast,
          bypassPermissions: [...DEFAULT_MAINTENANCE_CONFIG.bypassPermissions],
          bypassRoles: [...DEFAULT_MAINTENANCE_CONFIG.bypassRoles],
          bypassIps: [],
        },
      });

      const enableRes = await requestApi("POST", "/api/v1/maintenance/enable", {
        title: `Bảo trì Issue11 ${suffix}`,
      });
      assert.strictEqual(enableRes.status, 200);
      assert.strictEqual(enableRes.body.data.enabled, true);
      assert.ok(enableRes.body.data.startAt);
      assert.strictEqual(enableRes.body.data.estimatedEndAt, null);

      // 5. Disable maintenance and confirm DB, /public, and /config all return null timestamps
      const disableRes = await requestApi("POST", "/api/v1/maintenance/disable");
      assert.strictEqual(disableRes.status, 200);
      assert.strictEqual(disableRes.body.data.enabled, false);
      assert.strictEqual(disableRes.body.data.status, MAINTENANCE_STATUS.ONLINE);
      assert.strictEqual(disableRes.body.data.startAt, null);
      assert.strictEqual(disableRes.body.data.estimatedEndAt, null);

      const publicRes = await requestApi("GET", "/api/v1/maintenance/public");
      assert.strictEqual(publicRes.status, 200);
      assert.strictEqual(publicRes.body.data.startAt, null);
      assert.strictEqual(publicRes.body.data.estimatedEndAt, null);

      const cfgRes = await requestApi("GET", "/api/v1/maintenance/config");
      assert.strictEqual(cfgRes.status, 200);
      assert.strictEqual(cfgRes.body.data.startAt, null);
      assert.strictEqual(cfgRes.body.data.estimatedEndAt, null);
    });
  });
});
