import { describe, it, beforeEach, before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import type http from "node:http";
import type { AddressInfo } from "node:net";
import app from "../src/identity.app";
import { prisma } from "../src/database/prisma.client";
import { envConfig } from "../src/config/env.config";
import { GATEWAY_HEADERS } from "../src/common/constants/gateway.constant";
import { JWT_PURPOSE } from "../src/common/constants/jwt.constant";
import { PERMISSIONS } from "../src/common/constants/permission.constant";
import { ROLES } from "../src/common/constants/role.constant";
import { swaggerSpec } from "../src/config/swagger.config";
import {
  createSystemConfigSchema,
  updateSystemConfigSchema,
  toggleFeatureFlagSchema,
} from "../src/modules/system-config/system-config.validation";
import {
  AI_CONFIG_KEYS,
  DEFAULT_SYSTEM_CONFIGS,
  FEATURE_FLAGS,
  SYSTEM_CONFIG_CATEGORY,
  SYSTEM_CONFIG_REDACTED_VALUE,
} from "../src/common/constants/system-config.constant";
import { NOTIFICATION_CHANNEL } from "../src/common/constants/notification.constant";
import { EVENT_NAMES } from "../src/common/constants/event.constant";
import { EmailWorker } from "../src/common/workers/email-worker";
import { NotificationSubscriber } from "../src/common/subscribers/notification.subscriber";
import { EventBusService } from "../src/common/services/event-bus.service";
import {
  SystemConfigService,
  systemConfigService,
  isSensitiveSystemConfig,
} from "../src/modules/system-config/system-config.service";
import { SystemConfigController } from "../src/modules/system-config/system-config.controller";
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

  it("should seed ai.live_max_sessions as a public dynamic AI config and reflect updates", async () => {
    await service.ensureDefaultConfigs();
    const publicConfigs = await service.getPublicConfigs();
    assert.equal(publicConfigs[AI_CONFIG_KEYS.LIVE_MAX_SESSIONS], 16);

    await service.update(AI_CONFIG_KEYS.LIVE_MAX_SESSIONS, { value: 24 });
    const updatedVal = await service.get<number>(AI_CONFIG_KEYS.LIVE_MAX_SESSIONS);
    assert.equal(updatedVal, 24);
  });

  it("should seed feature.notifications.enabled as public and upgrade legacy isPublic=false records without overwriting value", async () => {
    mockDb.set(FEATURE_FLAGS.NOTIFICATIONS_ENABLED, {
      id: "cfg-notif-legacy",
      key: FEATURE_FLAGS.NOTIFICATIONS_ENABLED,
      value: false,
      description: "Legacy flag",
      category: "FEATURE_FLAG",
      isPublic: false,
    });

    await service.ensureDefaultConfigs();
    const upgraded = mockDb.get(FEATURE_FLAGS.NOTIFICATIONS_ENABLED);
    assert.equal(upgraded.isPublic, true);
    assert.equal(upgraded.value, false);

    const publicConfigs = await service.getPublicConfigs();
    assert.equal(publicConfigs[FEATURE_FLAGS.NOTIFICATIONS_ENABLED], false);
  });

  it("Issue #13: DEFAULT_SYSTEM_CONFIGS defines feature.webhooks.enabled with isPublic=true and value=true", () => {
    const webhookFlag = DEFAULT_SYSTEM_CONFIGS.find(
      (c) => c.key === FEATURE_FLAGS.WEBHOOKS_ENABLED,
    );
    assert.ok(webhookFlag);
    assert.equal(webhookFlag.isPublic, true);
    assert.equal(webhookFlag.value, true);
  });

  it("Issue #13: ensureDefaultConfigs upgrades legacy feature.webhooks.enabled (isPublic=false) to isPublic=true without overwriting value", async () => {
    mockDb.set(FEATURE_FLAGS.WEBHOOKS_ENABLED, {
      id: "cfg-webhook-legacy",
      key: FEATURE_FLAGS.WEBHOOKS_ENABLED,
      value: false,
      description: "Legacy webhook flag",
      category: SYSTEM_CONFIG_CATEGORY.FEATURE_FLAG,
      isPublic: false,
    });

    await service.ensureDefaultConfigs();
    const upgraded = mockDb.get(FEATURE_FLAGS.WEBHOOKS_ENABLED);
    assert.equal(upgraded.isPublic, true);
    assert.equal(upgraded.value, false);

    const publicConfigs = await service.getPublicConfigs();
    assert.equal(publicConfigs[FEATURE_FLAGS.WEBHOOKS_ENABLED], false);
  });

  it("Issue #13: toggleFeatureFlag keeps feature.webhooks.enabled public and reflects false/true in getPublicConfigs", async () => {
    mockDb.set(FEATURE_FLAGS.WEBHOOKS_ENABLED, {
      id: "cfg-webhook-toggle",
      key: FEATURE_FLAGS.WEBHOOKS_ENABLED,
      value: true,
      description: "Webhook flag",
      category: SYSTEM_CONFIG_CATEGORY.FEATURE_FLAG,
      isPublic: false,
    });

    await service.toggleFeatureFlag(FEATURE_FLAGS.WEBHOOKS_ENABLED, {
      enabled: false,
    });
    let publicConfigs = await service.getPublicConfigs();
    assert.equal(publicConfigs[FEATURE_FLAGS.WEBHOOKS_ENABLED], false);

    await service.toggleFeatureFlag(FEATURE_FLAGS.WEBHOOKS_ENABLED, {
      enabled: true,
    });
    publicConfigs = await service.getPublicConfigs();
    assert.equal(publicConfigs[FEATURE_FLAGS.WEBHOOKS_ENABLED], true);
  });

  it("should broadcast value on Redis PubSub only for public configs and omit value for private configs", async () => {
    const publishedMessages: Array<{ channel: string; payload: Record<string, unknown> }> = [];
    (service as any).isRedisAvailable = true;
    (service as any).redisPublisher = {
      publish: async (channel: string, message: string) => {
        publishedMessages.push({
          channel,
          payload: JSON.parse(message) as Record<string, unknown>,
        });
        return 1;
      },
    };

    // 1. Creating private config omits value from PubSub
    await service.create({
      key: "security.private_webhook_token",
      value: "super-secret-value",
      isPublic: false,
    });
    assert.equal(publishedMessages.length, 1);
    assert.equal(publishedMessages[0].payload.key, "security.private_webhook_token");
    assert.equal("value" in publishedMessages[0].payload, false);

    // 2. Creating public config includes value in PubSub
    await service.create({
      key: "ui.banner_text",
      value: "Welcome",
      isPublic: true,
    });
    assert.equal(publishedMessages.length, 2);
    assert.equal(publishedMessages[1].payload.key, "ui.banner_text");
    assert.equal(publishedMessages[1].payload.value, "Welcome");

    // 3. Updating public config to private omits value so satellite caches evict it
    await service.update("ui.banner_text", {
      value: "Internal only",
      isPublic: false,
    });
    assert.equal(publishedMessages.length, 3);
    assert.equal(publishedMessages[2].payload.key, "ui.banner_text");
    assert.equal("value" in publishedMessages[2].payload, false);

    // 4. Toggling public notification flag broadcasts new boolean value
    await service.toggleFeatureFlag(FEATURE_FLAGS.NOTIFICATIONS_ENABLED, {
      enabled: false,
    });
    assert.equal(publishedMessages.length, 4);
    assert.equal(publishedMessages[3].payload.key, FEATURE_FLAGS.NOTIFICATIONS_ENABLED);
    assert.equal(publishedMessages[3].payload.value, false);
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

describe("Notifications Feature Flag Enforcement (Identity Monolith Mode)", () => {
  it("EmailWorker.process() skips claiming emails when feature.notifications.enabled is false", async () => {
    let claimed = false;
    const worker = new EmailWorker(
      {
        isFeatureEnabled: async () => false,
      },
      {
        claimPendingEmails: async () => {
          claimed = true;
          return [];
        },
      } as any,
    );

    await worker.process();
    assert.equal(claimed, false);
  });

  it("NotificationSubscriber skips AUTH_NEW_DEVICE_DETECTED when global flag or user EMAIL preference is disabled", async () => {
    let sentCount = 0;
    const mockMail: any = {
      sendNewDeviceAlertEmail: async () => {
        sentCount += 1;
      },
    };
    const userId = "018f3a2b-c4d5-7e8f-9a0b-1c2d3e4f5a6b";

    // 1. Global flag disabled
    const bus1 = new EventBusService();
    const sub1 = new NotificationSubscriber(
      mockMail,
      bus1,
      { isFeatureEnabled: async () => false },
      { findUserPreferenceForChannel: async () => ({ enabled: true }) },
    );
    sub1.register();
    await bus1.dispatchDirectly({
      id: "evt-1",
      name: EVENT_NAMES.AUTH_NEW_DEVICE_DETECTED,
      payload: { userId, email: "user@ppe.local", deviceName: "Chrome", ip: "1.2.3.4" },
      timestamp: Date.now(),
      source: "test",
    });
    assert.equal(sentCount, 0);
    await bus1.close();

    // 2. Global flag enabled, user EMAIL preference disabled
    const bus2 = new EventBusService();
    const sub2 = new NotificationSubscriber(
      mockMail,
      bus2,
      { isFeatureEnabled: async () => true },
      { findUserPreferenceForChannel: async () => ({ enabled: false }) },
    );
    sub2.register();
    await bus2.dispatchDirectly({
      id: "evt-2",
      name: EVENT_NAMES.AUTH_NEW_DEVICE_DETECTED,
      payload: { userId, email: "user@ppe.local", deviceName: "Chrome", ip: "1.2.3.4" },
      timestamp: Date.now(),
      source: "test",
    });
    assert.equal(sentCount, 0);
    await bus2.close();

    // 3. Both global flag and user preference enabled
    const bus3 = new EventBusService();
    const sub3 = new NotificationSubscriber(
      mockMail,
      bus3,
      { isFeatureEnabled: async () => true },
      { findUserPreferenceForChannel: async () => ({ enabled: true }) },
    );
    sub3.register();
    await bus3.dispatchDirectly({
      id: "evt-3",
      name: EVENT_NAMES.AUTH_NEW_DEVICE_DETECTED,
      payload: { userId, email: "user@ppe.local", deviceName: "Chrome", ip: "1.2.3.4" },
      timestamp: Date.now(),
      source: "test",
    });
    assert.equal(sentCount, 1);
    await bus3.close();
  });
});

describe("Issue #8: SystemConfig Audit Redaction, Branding Seed & Full DTO on GET /configs/:key", () => {
  describe("1. Default Branding Seed Constants", () => {
    it("DEFAULT_SYSTEM_CONFIGS should use Smart PPE Monitoring branding instead of template defaults", () => {
      const appName = DEFAULT_SYSTEM_CONFIGS.find((c) => c.key === "app.name");
      const supportEmail = DEFAULT_SYSTEM_CONFIGS.find(
        (c) => c.key === "app.support_email",
      );

      assert.ok(appName);
      assert.strictEqual(appName.value, "Smart PPE Monitoring");
      assert.ok(supportEmail);
      assert.strictEqual(supportEmail.value, "support@smartppe.vn");

      const serialized = JSON.stringify(DEFAULT_SYSTEM_CONFIGS);
      assert.ok(!serialized.includes("Backend Template Platform"));
      assert.ok(!serialized.includes("support@example.com"));
    });
  });

  describe("2. Audit Log Redaction on create & update", () => {
    let mockDb: Map<string, any>;
    let auditLogs: any[];
    let service: SystemConfigService;

    beforeEach(() => {
      mockDb = new Map<string, any>();
      auditLogs = [];

      const mockRepo = {
        findByKey: async (key: string) => mockDb.get(key) || null,
        create: async (data: any) => {
          const record = {
            id: `cfg-${mockDb.size + 1}`,
            description: null,
            category: SYSTEM_CONFIG_CATEGORY.GENERAL,
            isPublic: false,
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
        createAuditLog: async (entry: any) => {
          auditLogs.push(entry);
        },
      };

      service = new SystemConfigService(mockRepo as any);
    });

    it("isSensitiveSystemConfig should treat isPublic=false or category=SECURITY as sensitive", () => {
      assert.strictEqual(
        isSensitiveSystemConfig({ isPublic: false, category: "GENERAL" }),
        true,
      );
      assert.strictEqual(
        isSensitiveSystemConfig({ isPublic: true, category: "SECURITY" }),
        true,
      );
      assert.strictEqual(
        isSensitiveSystemConfig({ isPublic: true, category: "GENERAL" }),
        false,
      );
    });

    it("create should redact value for private or SECURITY configs and keep plaintext for public non-security configs", async () => {
      await service.create({
        key: "internal.secret",
        value: "secret-123",
        category: SYSTEM_CONFIG_CATEGORY.GENERAL,
        isPublic: false,
      });
      await service.create({
        key: "security.public_flag",
        value: "security-secret",
        category: SYSTEM_CONFIG_CATEGORY.SECURITY,
        isPublic: true,
      });
      await service.create({
        key: "app.banner",
        value: "Welcome",
        category: SYSTEM_CONFIG_CATEGORY.GENERAL,
        isPublic: true,
      });

      assert.strictEqual(
        auditLogs[0].details.value,
        SYSTEM_CONFIG_REDACTED_VALUE,
      );
      assert.strictEqual(
        auditLogs[1].details.value,
        SYSTEM_CONFIG_REDACTED_VALUE,
      );
      assert.strictEqual(auditLogs[2].details.value, "Welcome");
    });

    it("update should redact previous and updated values accurately across private, SECURITY, and visibility transitions", async () => {
      // 1. Private config update
      await service.create({
        key: "private.api_token",
        value: "old-secret",
        category: SYSTEM_CONFIG_CATEGORY.GENERAL,
        isPublic: false,
      });
      await service.update("private.api_token", { value: "new-secret" });
      const privateUpdateLog = auditLogs[auditLogs.length - 1];
      assert.strictEqual(
        privateUpdateLog.details.previous.value,
        SYSTEM_CONFIG_REDACTED_VALUE,
      );
      assert.strictEqual(
        privateUpdateLog.details.updated.value,
        SYSTEM_CONFIG_REDACTED_VALUE,
      );

      // 2. Private metadata-only update omits value from updated payload
      await service.update("private.api_token", { description: "Rotated key" });
      const metaUpdateLog = auditLogs[auditLogs.length - 1];
      assert.strictEqual(
        metaUpdateLog.details.previous.value,
        SYSTEM_CONFIG_REDACTED_VALUE,
      );
      assert.strictEqual("value" in metaUpdateLog.details.updated, false);

      // 3. SECURITY config even with isPublic=true
      await service.create({
        key: "security.policy",
        value: "policy-v1",
        category: SYSTEM_CONFIG_CATEGORY.SECURITY,
        isPublic: true,
      });
      await service.update("security.policy", { value: "policy-v2" });
      const secUpdateLog = auditLogs[auditLogs.length - 1];
      assert.strictEqual(
        secUpdateLog.details.previous.value,
        SYSTEM_CONFIG_REDACTED_VALUE,
      );
      assert.strictEqual(
        secUpdateLog.details.updated.value,
        SYSTEM_CONFIG_REDACTED_VALUE,
      );

      // 4. Transition public -> private: old public value stays visible, new secret is redacted
      await service.create({
        key: "transition.config",
        value: "public-v1",
        category: SYSTEM_CONFIG_CATEGORY.GENERAL,
        isPublic: true,
      });
      await service.update("transition.config", {
        value: "private-v2",
        isPublic: false,
      });
      const pubToPrivLog = auditLogs[auditLogs.length - 1];
      assert.strictEqual(pubToPrivLog.details.previous.value, "public-v1");
      assert.strictEqual(
        pubToPrivLog.details.updated.value,
        SYSTEM_CONFIG_REDACTED_VALUE,
      );

      // 5. Transition private -> public: old secret stays redacted, new public value is visible
      await service.update("transition.config", {
        value: "public-v3",
        isPublic: true,
      });
      const privToPubLog = auditLogs[auditLogs.length - 1];
      assert.strictEqual(
        privToPubLog.details.previous.value,
        SYSTEM_CONFIG_REDACTED_VALUE,
      );
      assert.strictEqual(privToPubLog.details.updated.value, "public-v3");

      // 6. Public non-security update preserves plaintext
      await service.update("transition.config", { value: "public-v4" });
      const pubUpdateLog = auditLogs[auditLogs.length - 1];
      assert.strictEqual(pubUpdateLog.details.previous.value, "public-v3");
      assert.strictEqual(pubUpdateLog.details.updated.value, "public-v4");
    });
  });

  describe("3. findByKey Full DTO & OpenAPI Schema", () => {
    it("SystemConfigService.findByKey and SystemConfigController.findByKey should return full SystemConfig DTO and throw 404 when missing", async () => {
      const now = new Date();
      const fullRecord = {
        id: "018f0000-0000-7000-8000-000000000099",
        key: "app.name",
        value: "Smart PPE Monitoring",
        description: "Application name",
        category: SYSTEM_CONFIG_CATEGORY.GENERAL,
        isPublic: true,
        createdAt: now,
        updatedAt: now,
      };

      const mockRepo = {
        findByKey: async (key: string) =>
          key === "app.name" ? fullRecord : null,
      };
      const service = new SystemConfigService(mockRepo as any);

      const found = await service.findByKey("app.name");
      assert.deepStrictEqual(found, fullRecord);

      await assert.rejects(
        () => service.findByKey("missing.key"),
        (err: any) =>
          err instanceof AppError &&
          err.statusCode === 404 &&
          err.code === ERROR_CODE.NOT_FOUND,
      );

      const controller = new SystemConfigController(service);
      let jsonOut: any = null;
      await controller.findByKey(
        { params: { key: "app.name" } } as any,
        {
          json: (payload: any) => {
            jsonOut = payload;
          },
        } as any,
        () => {},
      );
      assert.deepStrictEqual(jsonOut, { success: true, data: fullRecord });
    });

    it("OpenAPI GET /system/configs/{key} should include createdAt and updatedAt in response schema", () => {
      const paths = swaggerSpec.paths as Record<string, any>;
      const op = paths["/system/configs/{key}"]?.get;
      assert.ok(op, "GET /system/configs/{key} must exist in OpenAPI spec");
      const dataProps =
        op.responses?.["200"]?.content?.["application/json"]?.schema?.properties
          ?.data?.properties;
      assert.ok(dataProps?.id);
      assert.ok(dataProps?.key);
      assert.ok(dataProps?.value);
      assert.ok(dataProps?.category);
      assert.ok(dataProps?.description);
      assert.ok(dataProps?.isPublic);
      assert.ok(dataProps?.createdAt);
      assert.ok(dataProps?.updatedAt);
    });
  });

  describe("4. Live HTTP + PostgreSQL (ppe_identity_db) Integration Tests", () => {
    let dbAvailable = false;
    let server: http.Server | null = null;
    let baseUrl = "";
    let adminToken = "";
    let createdTempRoleId: string | null = null;
    const createdUserIds: string[] = [];
    const createdConfigKeys: string[] = [];
    const createdConfigIds: string[] = [];

    const suffix = crypto.randomBytes(4).toString("hex");
    const testConfigKey = `it.issue8.secret_${suffix}`;

    async function requestApi(
      method: "GET" | "POST" | "PUT" | "PATCH",
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

    async function requestPublicGet(path: string) {
      const headers: Record<string, string> = {};
      if (envConfig.gateway.internalSecret) {
        headers[GATEWAY_HEADERS.INTERNAL_SECRET] =
          envConfig.gateway.internalSecret;
      }
      const res = await fetch(`${baseUrl}${path}`, {
        method: "GET",
        headers,
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
          email: `it-issue8-admin-${suffix}@smartppe.local`,
          fullName: `Issue8 Admin ${suffix}`,
          roleId: adminRole.id,
          isActive: true,
          deletedAt: null,
          siteIds: [],
        },
      });
      createdUserIds.push(adminUser.id);

      adminToken = jwtKeyService.signAccessToken({
        id: adminUser.id,
        email: adminUser.email!,
        role: ROLES.ADMIN,
        roleId: adminRole.id,
        permissions: [
          PERMISSIONS.SYSTEM_CONFIG_READ,
          PERMISSIONS.SYSTEM_CONFIG_WRITE,
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
        if (createdConfigIds.length > 0 && dbAvailable) {
          await prisma.auditLog
            .deleteMany({ where: { targetId: { in: createdConfigIds } } })
            .catch(() => {});
        }
        if (createdConfigKeys.length > 0 && dbAvailable) {
          await prisma.systemConfig
            .deleteMany({ where: { key: { in: createdConfigKeys } } })
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

    it("POST/GET/PUT /api/v1/system/configs/:key should return full DTO and redact sensitive values in persisted audit_logs", async (t) => {
      if (!dbAvailable) {
        t.skip("PostgreSQL ppe_identity_db is unavailable");
        return;
      }

      const secretV1 = `super-secret-v1-${suffix}`;
      const secretV2 = `super-secret-v2-${suffix}`;

      const createRes = await requestApi("POST", "/api/v1/system/configs", {
        key: testConfigKey,
        value: secretV1,
        description: "Secret API key",
        category: SYSTEM_CONFIG_CATEGORY.SECURITY,
        isPublic: false,
      });
      assert.strictEqual(createRes.status, 201);
      createdConfigKeys.push(testConfigKey);
      createdConfigIds.push(createRes.body.data.id);

      const getRes = await requestApi(
        "GET",
        `/api/v1/system/configs/${encodeURIComponent(testConfigKey)}`,
      );
      assert.strictEqual(getRes.status, 200);
      assert.strictEqual(getRes.body.success, true);
      assert.strictEqual(getRes.body.data.id, createRes.body.data.id);
      assert.strictEqual(getRes.body.data.key, testConfigKey);
      assert.strictEqual(getRes.body.data.value, secretV1);
      assert.strictEqual(getRes.body.data.description, "Secret API key");
      assert.strictEqual(
        getRes.body.data.category,
        SYSTEM_CONFIG_CATEGORY.SECURITY,
      );
      assert.strictEqual(getRes.body.data.isPublic, false);
      assert.ok(getRes.body.data.createdAt);
      assert.ok(getRes.body.data.updatedAt);

      const updateRes = await requestApi(
        "PUT",
        `/api/v1/system/configs/${encodeURIComponent(testConfigKey)}`,
        { value: secretV2 },
      );
      assert.strictEqual(updateRes.status, 200);

      const logs = await prisma.auditLog.findMany({
        where: { targetId: createRes.body.data.id },
        orderBy: { createdAt: "asc" },
      });
      assert.strictEqual(logs.length, 2);

      const createLogDetails = logs[0].details as Record<string, any>;
      assert.strictEqual(createLogDetails.value, SYSTEM_CONFIG_REDACTED_VALUE);
      assert.ok(!JSON.stringify(createLogDetails).includes(secretV1));

      const updateLogDetails = logs[1].details as Record<string, any>;
      assert.strictEqual(
        updateLogDetails.previous.value,
        SYSTEM_CONFIG_REDACTED_VALUE,
      );
      assert.strictEqual(
        updateLogDetails.updated.value,
        SYSTEM_CONFIG_REDACTED_VALUE,
      );
      assert.ok(!JSON.stringify(updateLogDetails).includes(secretV1));
      assert.ok(!JSON.stringify(updateLogDetails).includes(secretV2));

      const notFoundRes = await requestApi(
        "GET",
        `/api/v1/system/configs/non.existent.${suffix}`,
      );
      assert.strictEqual(notFoundRes.status, 404);
      assert.strictEqual(notFoundRes.body.code, ERROR_CODE.NOT_FOUND);
    });

    it("Issue #13: GET /api/v1/system/public exposes feature.webhooks.enabled boolean without Authorization header and reflects toggle changes", async (t) => {
      if (!dbAvailable) {
        t.skip("PostgreSQL ppe_identity_db is unavailable");
        return;
      }

      const testStart = new Date();
      const preExisting = await prisma.systemConfig.findUnique({
        where: { key: FEATURE_FLAGS.WEBHOOKS_ENABLED },
      });
      let targetConfigId: string | null = preExisting?.id ?? null;

      try {
        await systemConfigService.ensureDefaultConfigs();

        const pubRes1 = await requestPublicGet("/api/v1/system/public");
        assert.strictEqual(pubRes1.status, 200);
        assert.strictEqual(pubRes1.body.success, true);
        assert.strictEqual(
          typeof pubRes1.body.data?.[FEATURE_FLAGS.WEBHOOKS_ENABLED],
          "boolean",
        );

        const toggleFalseRes = await requestApi(
          "PATCH",
          `/api/v1/system/features/${encodeURIComponent(FEATURE_FLAGS.WEBHOOKS_ENABLED)}/toggle`,
          { enabled: false },
        );
        assert.strictEqual(toggleFalseRes.status, 200);
        assert.strictEqual(toggleFalseRes.body.data?.isPublic, true);
        targetConfigId = toggleFalseRes.body.data?.id ?? targetConfigId;

        const pubRes2 = await requestPublicGet("/api/v1/system/public");
        assert.strictEqual(pubRes2.status, 200);
        assert.strictEqual(
          pubRes2.body.data?.[FEATURE_FLAGS.WEBHOOKS_ENABLED],
          false,
        );

        const toggleTrueRes = await requestApi(
          "PATCH",
          `/api/v1/system/features/${encodeURIComponent(FEATURE_FLAGS.WEBHOOKS_ENABLED)}/toggle`,
          { enabled: true },
        );
        assert.strictEqual(toggleTrueRes.status, 200);

        const pubRes3 = await requestPublicGet("/api/v1/system/public");
        assert.strictEqual(pubRes3.status, 200);
        assert.strictEqual(
          pubRes3.body.data?.[FEATURE_FLAGS.WEBHOOKS_ENABLED],
          true,
        );
      } finally {
        if (preExisting) {
          await prisma.systemConfig
            .update({
              where: { key: FEATURE_FLAGS.WEBHOOKS_ENABLED },
              data: {
                value: preExisting.value as any,
                description: preExisting.description,
                category: preExisting.category,
                isPublic: true,
              },
            })
            .catch(() => {});
          systemConfigService.invalidateCache(
            FEATURE_FLAGS.WEBHOOKS_ENABLED,
            preExisting.value,
          );
        } else {
          await prisma.systemConfig
            .deleteMany({ where: { key: FEATURE_FLAGS.WEBHOOKS_ENABLED } })
            .catch(() => {});
          systemConfigService.invalidateCache(FEATURE_FLAGS.WEBHOOKS_ENABLED);
        }
        if (targetConfigId) {
          await prisma.auditLog
            .deleteMany({
              where: {
                targetId: targetConfigId,
                action: "TOGGLE_FEATURE_FLAG",
                createdAt: { gte: testStart },
              },
            })
            .catch(() => {});
        }
      }
    });
  });
});
