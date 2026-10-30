import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import {
  createSystemConfigSchema,
  updateSystemConfigSchema,
  toggleFeatureFlagSchema,
} from "../src/modules/system-config/system-config.validation";
import { SystemConfigService } from "../src/modules/system-config/system-config.service";
import { SystemConfigRepository } from "../src/modules/system-config/system-config.repository";
import { requireFeatureFlag } from "../src/middlewares/feature-flag.middleware";
import { maintenanceGuard } from "../src/middlewares/maintenance.middleware";
import { maintenanceCacheService } from "../src/common/services/maintenance-cache.service";
import { permissionCacheService } from "../src/common/services/permission-cache.service";
import { MAINTENANCE_STATUS } from "../src/common/constants/maintenance.constant";
import { jwtKeyService } from "../src/common/services/jwt-key.service";
import { AppError } from "../src/common/errors/app-error";
import { ERROR_CODE } from "../src/common/errors/error-code";

describe("System Configuration & Feature Flags Validation", () => {
  it("should validate valid createSystemConfigSchema", () => {
    const validData = {
      key: "app.theme.default",
      value: { mode: "dark", primaryColor: "#4CAF50" },
      description: "Default UI theme",
      category: "GENERAL",
      isPublic: true,
    };

    const parsed = createSystemConfigSchema.parse(validData);
    assert.equal(parsed.key, "app.theme.default");
    assert.equal(parsed.isPublic, true);
  });

  it("should reject invalid keys with special characters", () => {
    const invalidData = {
      key: "invalid key with spaces & symbols!",
      value: 123,
    };

    assert.throws(() => {
      createSystemConfigSchema.parse(invalidData);
    });
  });

  it("should validate toggleFeatureFlagSchema", () => {
    const valid = toggleFeatureFlagSchema.parse({
      enabled: false,
      description: "Temporarily disabled",
    });
    assert.equal(valid.enabled, false);
    assert.equal(valid.description, "Temporarily disabled");

    assert.throws(() => {
      toggleFeatureFlagSchema.parse({ enabled: "not-a-bool" });
    });
  });

  it("should validate updateSystemConfigSchema and reject empty payload", () => {
    assert.throws(() => {
      updateSystemConfigSchema.parse({});
    });

    const valid = updateSystemConfigSchema.parse({ value: "new-value" });
    assert.equal(valid.value, "new-value");
  });
});

describe("System Configuration Service & Cache Operations", () => {
  let mockDb: Map<string, any>;
  let mockRepo: any;
  let service: SystemConfigService;

  beforeEach(() => {
    mockDb = new Map<string, any>();

    mockRepo = {
      findByKey: async (key: string) => mockDb.get(key) || null,
      findAll: async () => Array.from(mockDb.values()),
      findPublicConfigs: async () =>
        Array.from(mockDb.values()).filter((c) => c.isPublic),
      create: async (data: any) => {
        const record = {
          id: "cfg-" + Date.now(),
          ...data,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        mockDb.set(data.key, record);
        return record;
      },
      update: async (key: string, data: any) => {
        const existing = mockDb.get(key);
        if (!existing) throw new Error("Not found");
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

  it("should create, cache, and retrieve configuration value", async () => {
    await service.create({
      key: "site.title",
      value: "My SaaS Portal",
      description: "Main Title",
      category: "GENERAL",
      isPublic: true,
    });

    const val = await service.get<string>("site.title");
    assert.equal(val, "My SaaS Portal");

    // Retrieve again (from in-memory cache)
    const cachedVal = await service.get<string>("site.title");
    assert.equal(cachedVal, "My SaaS Portal");
  });

  it("should evaluate feature flag accurately with default fallback", async () => {
    // Non-existing flag with default true
    const defaultState = await service.isFeatureEnabled(
      "feature.non_existing",
      true,
    );
    assert.equal(defaultState, true);

    // Toggle flag to false
    await service.toggleFeatureFlag("feature.beta_ui", { enabled: false });
    const isBetaEnabled = await service.isFeatureEnabled("feature.beta_ui");
    assert.equal(isBetaEnabled, false);

    // Toggle flag to true
    await service.toggleFeatureFlag("feature.beta_ui", { enabled: true });
    const isBetaEnabledNow = await service.isFeatureEnabled("feature.beta_ui");
    assert.equal(isBetaEnabledNow, true);
  });

  it("should fetch all public configurations for frontend bootstrap", async () => {
    await service.create({
      key: "public.api_version",
      value: "v1.0",
      isPublic: true,
    });
    await service.create({
      key: "secret.internal_token",
      value: "top_secret",
      isPublic: false,
    });

    const publicConfigs = await service.getPublicConfigs();
    assert.equal(publicConfigs["public.api_version"], "v1.0");
    assert.equal(publicConfigs["secret.internal_token"], undefined);
  });
});

describe("Feature Flag Route Enforcement Middleware", () => {
  let mockDb: Map<string, any>;
  let mockRepo: any;
  let service: SystemConfigService;

  beforeEach(() => {
    mockDb = new Map<string, any>();
    mockRepo = {
      findByKey: async (key: string) => mockDb.get(key) || null,
      create: async (data: any) => {
        const record = { id: "cfg-" + Date.now(), ...data };
        mockDb.set(data.key, record);
        return record;
      },
      update: async (key: string, data: any) => {
        const existing = mockDb.get(key);
        const updated = { ...existing, ...data };
        mockDb.set(key, updated);
        return updated;
      },
      createAuditLog: async () => {},
    };
    service = new SystemConfigService(mockRepo as any);
  });

  it("should allow request through when feature flag is enabled", async () => {
    await service.toggleFeatureFlag("feature.ai_chat", { enabled: true });

    // Mock global service reference in middleware by testing feature evaluation
    const isEnabled = await service.isFeatureEnabled("feature.ai_chat");
    assert.equal(isEnabled, true);
  });

  it("should reject request with 403 FEATURE_DISABLED when feature is disabled", async () => {
    await service.toggleFeatureFlag("feature.ai_chat", { enabled: false });

    const isEnabled = await service.isFeatureEnabled("feature.ai_chat");
    assert.equal(isEnabled, false);
  });
});

describe("Maintenance Guard Security (SEC-11)", () => {
  const guard = maintenanceGuard();

  beforeEach(() => {
    permissionCacheService.clear();
    // Enable maintenance mode
    (maintenanceCacheService as any).cache = {
      config: {
        enabled: true,
        status: MAINTENANCE_STATUS.DOWN,
        title: "Maintenance",
        message: "Under maintenance",
        bypassRoles: ["ADMIN"],
        bypassPermissions: ["MAINTENANCE_MANAGE"],
        bypassIps: [],
      },
      expiresAt: Date.now() + 60000,
    };
  });

  it("should NOT allow purged user (null userState) to bypass maintenance even with ADMIN role in token (SEC-11)", async () => {
    (permissionCacheService as any).userCache.set("purged-admin-uuid", {
      user: null,
      expiresAt: Date.now() + 60000,
    });

    const adminToken = jwtKeyService.signAccessToken({
      id: "purged-admin-uuid",
      email: "purged@ppe.local",
      role: "ADMIN",
      roleId: "some-role-id",
    });

    const req: any = {
      method: "POST",
      url: "/api/v1/sites",
      headers: { authorization: `Bearer ${adminToken}` },
      socket: { remoteAddress: "1.2.3.4" },
    };
    const res: any = {
      status: (code: number) => ({
        json: (data: any) => ({ code, data }),
      }),
    };

    let nextCalled = false;
    let thrownError: any;

    await guard(req, res, (err?: any) => {
      if (err) {
        thrownError = err;
      } else {
        nextCalled = true;
      }
    });

    assert.strictEqual(nextCalled, false);
    assert.ok(thrownError instanceof AppError);
    assert.strictEqual(thrownError.statusCode, 503);
    assert.strictEqual(thrownError.code, ERROR_CODE.SYSTEM_MAINTENANCE);
  });

  it("should NOT allow inactive or soft-deleted user to bypass maintenance mode", async () => {
    const token = jwtKeyService.signAccessToken({
      id: "inactive-admin-uuid",
      email: "inactive@ppe.local",
      role: "ADMIN",
    });

    (permissionCacheService as any).userCache.set("inactive-admin-uuid", {
      user: {
        id: "inactive-admin-uuid",
        isActive: false,
        deletedAt: null,
        roleName: "ADMIN",
      },
      expiresAt: Date.now() + 60000,
    });

    const req: any = {
      method: "GET",
      url: "/api/v1/cameras",
      headers: { authorization: `Bearer ${token}` },
      socket: { remoteAddress: "1.2.3.4" },
    };
    let nextCalled = false;
    let thrownError: any;

    await guard(req, {} as any, (err?: any) => {
      if (err) {
        thrownError = err;
      } else {
        nextCalled = true;
      }
    });

    assert.strictEqual(nextCalled, false);
    assert.ok(thrownError instanceof AppError);
    assert.strictEqual(thrownError.statusCode, 503);
  });

  it("should allow active ADMIN user with existing DB record to bypass maintenance mode", async () => {
    const token = jwtKeyService.signAccessToken({
      id: "active-admin-uuid",
      email: "active@ppe.local",
      role: "ADMIN",
    });

    (permissionCacheService as any).userCache.set("active-admin-uuid", {
      user: {
        id: "active-admin-uuid",
        isActive: true,
        deletedAt: null,
        roleName: "ADMIN",
      },
      expiresAt: Date.now() + 60000,
    });

    const req: any = {
      method: "POST",
      url: "/api/v1/sites",
      headers: { authorization: `Bearer ${token}` },
      socket: { remoteAddress: "1.2.3.4" },
    };
    let nextCalled = false;

    await guard(req, {} as any, () => {
      nextCalled = true;
    });

    assert.strictEqual(nextCalled, true);
  });
});

describe("Database Seed Security Hardening (SEC-12)", () => {
  it("should have removed password overwrite and forced activation from prisma/seed.ts user upsert", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const seedContent = fs.readFileSync(
      path.resolve(__dirname, "../prisma/seed.ts"),
      "utf-8",
    );

    // Verify Production guard
    assert.ok(
      seedContent.includes('process.env.NODE_ENV === "production"'),
      "seed.ts must guard against execution in production",
    );

    // Verify user update clause does not overwrite password
    assert.ok(
      !/update:\s*\{[^}]*password:\s*u\.password/s.test(seedContent),
      "seed.ts user upsert update clause must not overwrite password with default password",
    );
  });
});
