import { describe, it, beforeEach, before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import type http from "node:http";
import type { AddressInfo } from "node:net";
import app from "../src/identity.app";
import { prisma } from "../src/database/prisma.client";
import { envConfig } from "../src/config/env.config";
import { jwtKeyService } from "../src/common/services/jwt-key.service";
import { GATEWAY_HEADERS } from "../src/common/constants/gateway.constant";
import { JWT_PURPOSE } from "../src/common/constants/jwt.constant";
import { ROLES } from "../src/common/constants/role.constant";
import { PERMISSIONS } from "../src/common/constants/permission.constant";
import { FEATURE_FLAGS } from "../src/common/constants/system-config.constant";
import { EVENT_NAMES } from "../src/common/constants/event.constant";
import {
  WEBHOOK_EVENTS,
  WEBHOOK_STATUS,
} from "../src/common/constants/integration.constant";
import { AUDIT_ACTION } from "../src/common/constants/audit-log.constant";
import { ERROR_CODE } from "../src/common/errors/error-code";
import { AppError } from "../src/common/errors/app-error";
import { permissionCacheService } from "../src/common/services/permission-cache.service";
import { systemConfigService } from "../src/modules/system-config/system-config.service";
import { EventBusService } from "../src/common/services/event-bus.service";
import { WebhookSubscriber } from "../src/common/subscribers/webhook.subscriber";
import { webhookQueue } from "../src/common/queues/webhook.queue";
import { WebhookWorker } from "../src/common/workers/webhook.worker";
import {
  IntegrationService,
  integrationService,
  maskWebhookSecret,
} from "../src/modules/integration/integration.service";
import { IntegrationController } from "../src/modules/integration/integration.controller";
import { integrationRepository } from "../src/modules/integration/integration.repository";
import integrationRouter from "../src/modules/integration/integration.route";
import { AuthService } from "../src/modules/auth/auth.service";
import { UserService } from "../src/modules/users/user.service";
import { encryptSecret } from "../src/common/helpers/crypto.helper";

describe("Issue #9: Integration API Key Escalation, BullMQ Retry, WEBHOOKS_ENABLED, Real Events & Audit Metadata", () => {
  beforeEach(() => {
    permissionCacheService.clear();
  });

  describe("1. API Key Privilege Escalation Prevention", () => {
    it("should reject non-admin creating API key with permissions they do not own (403 FORBIDDEN)", async () => {
      const mockRepo = {
        createApiKey: async () => {
          throw new Error("Should not reach createApiKey");
        },
        createAuditLog: async () => ({}) as any,
      } as any;

      const mockPermissionCache = {
        getUserState: async () => ({
          id: "u-operator",
          isActive: true,
          deletedAt: null,
          roleId: "r-operator",
          roleName: ROLES.OPERATOR,
        }),
        getRolePermissions: async () =>
          new Set([PERMISSIONS.API_KEY_MANAGE, PERMISSIONS.USER_READ]),
      };

      const service = new IntegrationService(
        mockRepo,
        mockPermissionCache,
        { isFeatureEnabled: async () => true },
        { enqueue: async () => ({ jobId: "j-1" }) },
      );

      for (const escalatedPerm of [
        PERMISSIONS.USER_DELETE,
        PERMISSIONS.ROLE_PERMISSION_ASSIGN,
        PERMISSIONS.SYSTEM_CONFIG_WRITE,
      ]) {
        await assert.rejects(
          () =>
            service.createApiKey("u-operator", {
              name: "Escalated Key",
              permissions: [PERMISSIONS.USER_READ, escalatedPerm],
            }),
          (err: any) =>
            err instanceof AppError &&
            err.statusCode === 403 &&
            err.code === ERROR_CODE.FORBIDDEN,
        );
      }
    });

    it("should allow non-admin creating API key with subset of owned permissions or empty array", async () => {
      const createdPayloads: any[] = [];
      const mockRepo = {
        createApiKey: async (data: any) => {
          createdPayloads.push(data);
          return {
            id: "ak-1",
            name: data.name,
            prefix: data.prefix,
            permissions: data.permissions,
            expiresAt: data.expiresAt,
            createdAt: new Date(),
          };
        },
        createAuditLog: async () => ({}) as any,
      } as any;

      const mockPermissionCache = {
        getUserState: async () => ({
          id: "u-operator",
          isActive: true,
          deletedAt: null,
          roleId: "r-operator",
          roleName: ROLES.OPERATOR,
        }),
        getRolePermissions: async () =>
          new Set([PERMISSIONS.API_KEY_MANAGE, PERMISSIONS.USER_READ]),
      };

      const service = new IntegrationService(
        mockRepo,
        mockPermissionCache,
        { isFeatureEnabled: async () => true },
        { enqueue: async () => ({ jobId: "j-1" }) },
      );

      const resSubset = await service.createApiKey("u-operator", {
        name: "Read Key",
        permissions: [PERMISSIONS.USER_READ, PERMISSIONS.USER_READ],
      });
      assert.deepStrictEqual(resSubset.permissions, [PERMISSIONS.USER_READ]);

      const resEmpty = await service.createApiKey("u-operator", {
        name: "Empty Key",
        permissions: [],
      });
      assert.deepStrictEqual(resEmpty.permissions, []);
    });

    it("should allow ADMIN to create API key with any valid permission and reject inactive/deleted users", async () => {
      const mockRepo = {
        createApiKey: async (data: any) => ({
          id: "ak-admin",
          name: data.name,
          prefix: data.prefix,
          permissions: data.permissions,
          expiresAt: data.expiresAt,
          createdAt: new Date(),
        }),
        createAuditLog: async () => ({}) as any,
      } as any;

      const adminService = new IntegrationService(
        mockRepo,
        {
          getUserState: async () => ({
            id: "u-admin",
            isActive: true,
            deletedAt: null,
            roleId: "r-admin",
            roleName: ROLES.ADMIN,
          }),
          getRolePermissions: async () => new Set(),
        },
        { isFeatureEnabled: async () => true },
        { enqueue: async () => ({ jobId: "j-1" }) },
      );

      const adminRes = await adminService.createApiKey("u-admin", {
        name: "Admin Key",
        permissions: [
          PERMISSIONS.ROLE_PERMISSION_ASSIGN,
          PERMISSIONS.SYSTEM_CONFIG_WRITE,
        ],
      });
      assert.deepStrictEqual(adminRes.permissions, [
        PERMISSIONS.ROLE_PERMISSION_ASSIGN,
        PERMISSIONS.SYSTEM_CONFIG_WRITE,
      ]);

      const inactiveService = new IntegrationService(
        mockRepo,
        {
          getUserState: async () => ({
            id: "u-inactive",
            isActive: false,
            deletedAt: null,
            roleId: "r-op",
            roleName: ROLES.OPERATOR,
          }),
          getRolePermissions: async () => new Set([PERMISSIONS.USER_READ]),
        },
        { isFeatureEnabled: async () => true },
        { enqueue: async () => ({ jobId: "j-1" }) },
      );

      await assert.rejects(
        () =>
          inactiveService.createApiKey("u-inactive", {
            name: "Dead Key",
            permissions: [],
          }),
        (err: any) =>
          err instanceof AppError &&
          err.statusCode === 403 &&
          err.code === ERROR_CODE.FORBIDDEN,
      );
    });
  });

  describe("2. BullMQ Retry Deduplication Fix", () => {
    it("webhookQueue.enqueue with isRetry should remove stale failed job and assign unique hyphenated retry jobIds", async () => {
      const originalQueue = (webhookQueue as any).queue;
      const originalIsRedisAvailable = (webhookQueue as any).isRedisAvailable;

      let removedJobId: string | null = null;
      const addedJobs: Array<{ name: string; jobId: string }> = [];

      const mockQueue = {
        getJob: async (id: string) => ({
          id,
          getState: async () => "failed",
          remove: async () => {
            removedJobId = id;
          },
        }),
        add: async (name: string, _data: any, opts: { jobId: string }) => {
          addedJobs.push({ name, jobId: opts.jobId });
          return { id: opts.jobId };
        },
      };

      (webhookQueue as any).queue = mockQueue;
      (webhookQueue as any).isRedisAvailable = true;

      try {
        const deliveryId = "018f0000-0000-7000-8000-000000000999";
        const jobData = {
          deliveryId,
          webhookEndpointId: "wh-1",
          userId: "u-1",
          event: WEBHOOK_EVENTS.SYSTEM_PING,
          url: "https://example.com/webhook",
          encryptedSecret: "enc",
          payload: { ok: true },
        };

        const r1 = await webhookQueue.enqueue(jobData, { isRetry: true });
        const r2 = await webhookQueue.enqueue(jobData, { isRetry: true });

        assert.strictEqual(removedJobId, deliveryId);
        assert.strictEqual(addedJobs.length, 2);
        assert.ok(r1.jobId.startsWith(`${deliveryId}-retry-`));
        assert.ok(r2.jobId.startsWith(`${deliveryId}-retry-`));
        assert.notStrictEqual(r1.jobId, r2.jobId);
        assert.strictEqual(r1.jobId.includes(":"), false);
        assert.strictEqual(r2.jobId.includes(":"), false);
      } finally {
        (webhookQueue as any).queue = originalQueue;
        (webhookQueue as any).isRedisAvailable = originalIsRedisAvailable;
      }
    });

    it("IntegrationService.retryDelivery should reset DB status to PENDING and enqueue with isRetry: true", async () => {
      const statusUpdates: any[] = [];
      const enqueuedCalls: any[] = [];
      const auditCalls: any[] = [];

      const mockRepo = {
        findDeliveryById: async () => ({
          id: "deliv-100",
          webhookEndpointId: "wh-100",
          event: WEBHOOK_EVENTS.USER_UPDATED,
          payload: { userId: "u-1" },
          webhookEndpoint: {
            url: "https://example.com/hook",
            encryptedSecret: "enc-secret",
          },
        }),
        updateDeliveryStatus: async (id: string, data: any) => {
          statusUpdates.push({ id, data });
        },
        createAuditLog: async (entry: any) => {
          auditCalls.push(entry);
        },
      } as any;

      const service = new IntegrationService(
        mockRepo,
        {
          getUserState: async () => null,
          getRolePermissions: async () => new Set(),
        },
        { isFeatureEnabled: async () => true },
        {
          enqueue: async (data, opts) => {
            enqueuedCalls.push({ data, opts });
            return { jobId: "deliv-100-retry-1" };
          },
        },
      );

      await service.retryDelivery("u-1", "deliv-100", {
        ipAddress: "10.0.0.1",
        userAgent: "TestAgent",
      });

      assert.strictEqual(statusUpdates.length, 1);
      assert.strictEqual(statusUpdates[0].data.status, WEBHOOK_STATUS.PENDING);
      assert.strictEqual(statusUpdates[0].data.attempts, 0);
      assert.strictEqual(enqueuedCalls.length, 1);
      assert.deepStrictEqual(enqueuedCalls[0].opts, { isRetry: true });
      assert.strictEqual(auditCalls[0].ipAddress, "10.0.0.1");
      assert.strictEqual(auditCalls[0].userAgent, "TestAgent");
    });
  });

  describe("3. FEATURE_FLAGS.WEBHOOKS_ENABLED Enforcement", () => {
    it("IntegrationService should skip dispatch and reject testPingWebhook / retryDelivery when WEBHOOKS_ENABLED is false", async () => {
      let createDeliveryCalled = false;
      let enqueueCalled = false;

      const mockRepo = {
        findActiveWebhooksForUser: async () => {
          throw new Error("Should not query webhooks when disabled");
        },
        findActiveWebhooksForBroadcast: async () => {
          throw new Error("Should not query webhooks when disabled");
        },
        createDelivery: async () => {
          createDeliveryCalled = true;
          return { id: "d-1" };
        },
      } as any;

      const service = new IntegrationService(
        mockRepo,
        {
          getUserState: async () => null,
          getRolePermissions: async () => new Set(),
        },
        {
          isFeatureEnabled: async (key: string) =>
            key === FEATURE_FLAGS.WEBHOOKS_ENABLED ? false : true,
        },
        {
          enqueue: async () => {
            enqueueCalled = true;
            return { jobId: "j-1" };
          },
        },
      );

      const d1 = await service.dispatchWebhookEvent(
        "u-1",
        WEBHOOK_EVENTS.JOB_COMPLETED,
        { ok: true },
      );
      const d2 = await service.dispatchDomainWebhookEvent(
        WEBHOOK_EVENTS.PPE_INCIDENT_CREATED,
        { incidentId: "inc-1" },
      );

      assert.deepStrictEqual(d1, { dispatchedCount: 0, deliveryIds: [] });
      assert.deepStrictEqual(d2, { dispatchedCount: 0, deliveryIds: [] });
      assert.strictEqual(createDeliveryCalled, false);
      assert.strictEqual(enqueueCalled, false);

      await assert.rejects(
        () => service.testPingWebhook("u-1", "wh-1"),
        (err: any) =>
          err instanceof AppError &&
          err.statusCode === 403 &&
          err.code === ERROR_CODE.FEATURE_DISABLED,
      );

      await assert.rejects(
        () => service.retryDelivery("u-1", "deliv-1"),
        (err: any) =>
          err instanceof AppError &&
          err.statusCode === 403 &&
          err.code === ERROR_CODE.FEATURE_DISABLED,
      );
    });

    it("WebhookWorker.processJob should skip outbound HTTP request and mark FAILED when WEBHOOKS_ENABLED is false", async () => {
      const originalUpdateDeliveryStatus =
        integrationRepository.updateDeliveryStatus;
      const updates: any[] = [];
      integrationRepository.updateDeliveryStatus = async (
        id: string,
        data: any,
      ) => {
        updates.push({ id, data });
        return {} as any;
      };

      let fetcherCalled = false;
      const worker = new WebhookWorker({
        isFeatureEnabled: async () => false,
      });

      try {
        const result = await worker.processJob(
          {
            deliveryId: "deliv-ff-1",
            webhookEndpointId: "wh-ff-1",
            userId: "u-1",
            event: WEBHOOK_EVENTS.SYSTEM_PING,
            url: "https://example.com/webhook",
            encryptedSecret: encryptSecret("whsec_test_secret_123456"),
            payload: { ping: true },
          },
          0,
          async () => {
            fetcherCalled = true;
            return new Response("ok", { status: 200 });
          },
        );

        assert.strictEqual(fetcherCalled, false);
        assert.strictEqual(result.success, false);
        assert.match(result.error || "", /Webhook delivery skipped/);
        assert.strictEqual(updates.length, 1);
        assert.strictEqual(updates[0].data.status, WEBHOOK_STATUS.FAILED);
      } finally {
        integrationRepository.updateDeliveryStatus =
          originalUpdateDeliveryStatus;
      }
    });

    it("integrationRouter should mount requireFeatureFlag on POST /webhooks/:id/test and POST /webhooks/deliveries/:deliveryId/retry", () => {
      const testRoute = integrationRouter.stack.find(
        (l: any) =>
          l.route &&
          l.route.path === "/webhooks/:id/test" &&
          l.route.methods.post,
      );
      const retryRoute = integrationRouter.stack.find(
        (l: any) =>
          l.route &&
          l.route.path === "/webhooks/deliveries/:deliveryId/retry" &&
          l.route.methods.post,
      );

      assert.ok(testRoute && testRoute.route.stack.length >= 5);
      assert.ok(retryRoute && retryRoute.route.stack.length >= 5);
    });
  });

  describe("4. Real Webhook Events Wiring (ppe.incident.* & user.updated)", () => {
    it("WEBHOOK_EVENTS should include ppe.incident.created, ppe.incident.assigned, and ppe.incident.resolved", () => {
      assert.strictEqual(
        WEBHOOK_EVENTS.PPE_INCIDENT_CREATED,
        "ppe.incident.created",
      );
      assert.strictEqual(
        WEBHOOK_EVENTS.PPE_INCIDENT_ASSIGNED,
        "ppe.incident.assigned",
      );
      assert.strictEqual(
        WEBHOOK_EVENTS.PPE_INCIDENT_RESOLVED,
        "ppe.incident.resolved",
      );
      assert.strictEqual(WEBHOOK_EVENTS.USER_UPDATED, "user.updated");
    });

    it("WebhookSubscriber should dispatch ppe.incident.* events via dispatchDomainWebhookEvent with broadcast scope", async () => {
      const bus = new EventBusService();
      const dispatched: Array<{ event: string; payload: any; options: any }> =
        [];

      const subscriber = new WebhookSubscriber(bus, {
        dispatchDomainWebhookEvent: async (event, payload, options) => {
          dispatched.push({ event, payload, options });
          return { dispatchedCount: 1, deliveryIds: ["d-1"] };
        },
      });
      subscriber.register();

      try {
        await bus.dispatchDirectly({
          id: "evt-inc-1",
          name: EVENT_NAMES.PPE_INCIDENT_CREATED,
          payload: {
            incidentId: "inc-1",
            siteId: "site-1",
            cameraId: "cam-1",
            violationType: "NO_HELMET",
            severity: "HIGH",
            detectedAt: new Date().toISOString(),
          },
          timestamp: Date.now(),
          source: "incident-service",
        });

        await bus.dispatchDirectly({
          id: "evt-inc-2",
          name: EVENT_NAMES.PPE_INCIDENT_ASSIGNED,
          payload: {
            incidentId: "inc-1",
            assignedTo: "u-officer",
            assignedBy: "u-manager",
          },
          timestamp: Date.now(),
          source: "incident-service",
        });

        await bus.dispatchDirectly({
          id: "evt-inc-3",
          name: EVENT_NAMES.PPE_INCIDENT_RESOLVED,
          payload: {
            incidentId: "inc-1",
            resolvedBy: "u-officer",
            resolutionNote: "Fixed",
            resolvedAt: new Date().toISOString(),
          },
          timestamp: Date.now(),
          source: "incident-service",
        });

        assert.strictEqual(dispatched.length, 3);
        assert.strictEqual(
          dispatched[0].event,
          WEBHOOK_EVENTS.PPE_INCIDENT_CREATED,
        );
        assert.strictEqual(
          dispatched[1].event,
          WEBHOOK_EVENTS.PPE_INCIDENT_ASSIGNED,
        );
        assert.strictEqual(
          dispatched[2].event,
          WEBHOOK_EVENTS.PPE_INCIDENT_RESOLVED,
        );
        for (const call of dispatched) {
          assert.deepStrictEqual(call.options, { scope: "broadcast" });
        }
      } finally {
        await bus.close();
      }
    });

    it("AuthService.updateProfile and UserService.update should dispatch non-sensitive user.updated webhook", async () => {
      const originalDispatch = integrationService.dispatchDomainWebhookEvent;
      const calls: Array<{ event: string; payload: any; options: any }> = [];

      integrationService.dispatchDomainWebhookEvent = async (
        event,
        payload,
        options,
      ) => {
        calls.push({ event, payload, options });
        return { dispatchedCount: 0, deliveryIds: [] };
      };

      try {
        const authService = new AuthService({
          findById: async (id: string) =>
            ({ id, email: "u@ppe.vn", isActive: true }) as any,
          updateProfile: async () => ({}) as any,
        } as any);

        await authService.updateProfile("u-self", { fullName: "Updated Name" });

        const userService = new UserService({
          findById: async (id: string) =>
            ({
              id,
              email: "u@ppe.vn",
              isActive: true,
              role: { name: ROLES.USER },
            }) as any,
          update: async (id: string, data: any) => ({ id, ...data }) as any,
        } as any);

        await userService.update(
          "u-target",
          { fullName: "Admin Updated" },
          "u-admin",
        );

        assert.strictEqual(calls.length, 2);
        assert.strictEqual(calls[0].event, WEBHOOK_EVENTS.USER_UPDATED);
        assert.strictEqual(calls[0].payload.source, "SELF_PROFILE_UPDATE");
        assert.deepStrictEqual(calls[0].payload.updatedFields, ["fullName"]);
        assert.deepStrictEqual(calls[0].options, {
          scope: "users_or_admins",
          userIds: ["u-self"],
        });

        assert.strictEqual(calls[1].event, WEBHOOK_EVENTS.USER_UPDATED);
        assert.strictEqual(calls[1].payload.source, "ADMIN_USER_UPDATE");
        assert.deepStrictEqual(calls[1].payload.updatedFields, ["fullName"]);
        assert.deepStrictEqual(calls[1].options, {
          scope: "users_or_admins",
          userIds: ["u-target", "u-admin"],
        });
      } finally {
        integrationService.dispatchDomainWebhookEvent = originalDispatch;
      }
    });
  });

  describe("5. secretMasked & Controller Audit Metadata", () => {
    it("maskWebhookSecret should mask whsec_ secrets and custom secrets without forcing whsec_ prefix", () => {
      assert.strictEqual(
        maskWebhookSecret("whsec_abcdef1234567890"),
        "whsec_abcdef...",
      );
      assert.strictEqual(
        maskWebhookSecret("my_custom_webhook_secret_2026"),
        "my_c••••••••",
      );
      assert.strictEqual(
        maskWebhookSecret("short_sec").startsWith("whsec_"),
        false,
      );
    });

    it("IntegrationController should forward ipAddress and userAgent on all mutating handlers", async () => {
      const capturedMetadata: Array<{ op: string; meta: any }> = [];
      const mockService = {
        createApiKey: async (_u: string, _d: any, meta: any) => {
          capturedMetadata.push({ op: "createApiKey", meta });
          return {};
        },
        deleteApiKey: async (_u: string, _id: string, meta: any) => {
          capturedMetadata.push({ op: "deleteApiKey", meta });
        },
        toggleApiKey: async (
          _u: string,
          _id: string,
          _a: boolean,
          meta: any,
        ) => {
          capturedMetadata.push({ op: "toggleApiKey", meta });
        },
        createWebhook: async (_u: string, _d: any, meta: any) => {
          capturedMetadata.push({ op: "createWebhook", meta });
          return {};
        },
        updateWebhook: async (_u: string, _id: string, _d: any, meta: any) => {
          capturedMetadata.push({ op: "updateWebhook", meta });
        },
        deleteWebhook: async (_u: string, _id: string, meta: any) => {
          capturedMetadata.push({ op: "deleteWebhook", meta });
        },
        retryDelivery: async (_u: string, _id: string, meta: any) => {
          capturedMetadata.push({ op: "retryDelivery", meta });
          return {};
        },
      } as unknown as IntegrationService;

      const controller = new IntegrationController(mockService);
      const req: any = {
        user: { id: "u-1" },
        params: { id: "id-1", deliveryId: "deliv-1" },
        body: { isActive: true },
        ip: "203.0.113.10",
        headers: { "user-agent": "Issue9-Test/1.0" },
      };
      const res: any = {
        status: () => res,
        json: () => res,
      };
      const next = () => {};

      await controller.createApiKey(req, res, next);
      await controller.deleteApiKey(req, res, next);
      await controller.toggleApiKey(req, res, next);
      await controller.createWebhook(req, res, next);
      await controller.updateWebhook(req, res, next);
      await controller.deleteWebhook(req, res, next);
      await controller.retryDelivery(req, res, next);

      assert.strictEqual(capturedMetadata.length, 7);
      for (const item of capturedMetadata) {
        assert.deepStrictEqual(item.meta, {
          ipAddress: "203.0.113.10",
          userAgent: "Issue9-Test/1.0",
        });
      }
    });
  });

  describe("6. Live HTTP + PostgreSQL (ppe_identity_db) Integration Tests", () => {
    let dbAvailable = false;
    let server: http.Server | null = null;
    let baseUrl = "";
    let operatorToken = "";
    let operatorId = "";
    let operatorRoleId = "";
    let createdTempRoleId: string | null = null;
    const createdUserIds: string[] = [];
    const createdApiKeyIds: string[] = [];
    const createdWebhookIds: string[] = [];

    const suffix = crypto.randomBytes(4).toString("hex");

    async function requestApi(
      method: "GET" | "POST" | "DELETE",
      path: string,
      body?: unknown,
    ) {
      const headers: Record<string, string> = {
        authorization: `Bearer ${operatorToken}`,
        "user-agent": `Issue9-LiveTest/${suffix}`,
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

      // Create an isolated non-admin role with API_KEY_MANAGE, USER_READ, WEBHOOK_MANAGE
      const tempRole = await prisma.role.create({
        data: {
          name: `ISSUE9_OP_${suffix.toUpperCase()}`,
          description: "Temporary Issue #9 non-admin role",
          isSystem: false,
        },
      });
      createdTempRoleId = tempRole.id;
      operatorRoleId = tempRole.id;

      const permRecords = await prisma.permission.findMany({
        where: {
          name: {
            in: [
              PERMISSIONS.API_KEY_MANAGE,
              PERMISSIONS.USER_READ,
              PERMISSIONS.WEBHOOK_MANAGE,
            ],
          },
        },
      });

      if (permRecords.length > 0) {
        await prisma.rolePermission.createMany({
          data: permRecords.map((p) => ({
            roleId: tempRole.id,
            permissionId: p.id,
          })),
        });
      }

      const operatorUser = await prisma.user.create({
        data: {
          email: `it-issue9-op-${suffix}@smartppe.local`,
          fullName: `Issue9 Operator ${suffix}`,
          roleId: operatorRoleId,
          isActive: true,
          deletedAt: null,
          siteIds: [],
        },
      });
      operatorId = operatorUser.id;
      createdUserIds.push(operatorUser.id);

      // Seed role permission cache cleanly for the test role
      (permissionCacheService as any).cache.set(operatorRoleId, {
        permissions: new Set([
          PERMISSIONS.API_KEY_MANAGE,
          PERMISSIONS.USER_READ,
          PERMISSIONS.WEBHOOK_MANAGE,
        ]),
        expiresAt: Date.now() + 60_000,
      });

      operatorToken = jwtKeyService.signAccessToken({
        id: operatorUser.id,
        email: operatorUser.email!,
        role: tempRole.name,
        roleId: operatorRoleId,
        permissions: [
          PERMISSIONS.API_KEY_MANAGE,
          PERMISSIONS.USER_READ,
          PERMISSIONS.WEBHOOK_MANAGE,
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
        if (createdApiKeyIds.length > 0 && dbAvailable) {
          await prisma.auditLog
            .deleteMany({ where: { targetId: { in: createdApiKeyIds } } })
            .catch(() => {});
          await prisma.apiKey
            .deleteMany({ where: { id: { in: createdApiKeyIds } } })
            .catch(() => {});
        }
        if (createdWebhookIds.length > 0 && dbAvailable) {
          await prisma.webhookDelivery
            .deleteMany({
              where: { webhookEndpointId: { in: createdWebhookIds } },
            })
            .catch(() => {});
          await prisma.webhookEndpoint
            .deleteMany({ where: { id: { in: createdWebhookIds } } })
            .catch(() => {});
        }
        if (createdUserIds.length > 0 && dbAvailable) {
          await prisma.auditLog
            .deleteMany({ where: { actorId: { in: createdUserIds } } })
            .catch(() => {});
          await prisma.user
            .deleteMany({ where: { id: { in: createdUserIds } } })
            .catch(() => {});
        }
        if (createdTempRoleId && dbAvailable) {
          await prisma.rolePermission
            .deleteMany({ where: { roleId: createdTempRoleId } })
            .catch(() => {});
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

    it("POST /api/v1/integration/api-keys should block privilege escalation with 403 and persist audit metadata on allowed subset", async (t) => {
      if (!dbAvailable) {
        t.skip("PostgreSQL ppe_identity_db is unavailable");
        return;
      }

      const escalatedRes = await requestApi(
        "POST",
        "/api/v1/integration/api-keys",
        {
          name: `Escalated-${suffix}`,
          permissions: [PERMISSIONS.USER_DELETE],
        },
      );
      assert.strictEqual(escalatedRes.status, 403);
      assert.strictEqual(escalatedRes.body.code, ERROR_CODE.FORBIDDEN);

      const allowedRes = await requestApi(
        "POST",
        "/api/v1/integration/api-keys",
        {
          name: `Subset-${suffix}`,
          permissions: [PERMISSIONS.USER_READ],
        },
      );
      assert.strictEqual(allowedRes.status, 201);
      createdApiKeyIds.push(allowedRes.body.data.id);

      const audit = await prisma.auditLog.findFirst({
        where: {
          targetId: allowedRes.body.data.id,
          action: AUDIT_ACTION.CREATE_API_KEY,
        },
      });
      assert.ok(audit, "Expected CREATE_API_KEY audit log");
      assert.ok(audit.ipAddress, "Expected non-null ipAddress on audit log");
      assert.strictEqual(audit.userAgent, `Issue9-LiveTest/${suffix}`);
    });

    it("POST /webhooks/:id/test and /webhooks/deliveries/:deliveryId/retry should return 403 FEATURE_DISABLED when WEBHOOKS_ENABLED is false", async (t) => {
      if (!dbAvailable) {
        t.skip("PostgreSQL ppe_identity_db is unavailable");
        return;
      }

      const webhook = await prisma.webhookEndpoint.create({
        data: {
          userId: operatorId,
          url: "https://example.com/hook",
          encryptedSecret: encryptSecret("whsec_live_test_secret_1234"),
          events: [WEBHOOK_EVENTS.SYSTEM_PING],
          isActive: true,
        },
      });
      createdWebhookIds.push(webhook.id);

      const delivery = await prisma.webhookDelivery.create({
        data: {
          webhookEndpointId: webhook.id,
          userId: operatorId,
          event: WEBHOOK_EVENTS.SYSTEM_PING,
          payload: { ping: true },
          signature: "sig",
          status: WEBHOOK_STATUS.FAILED,
        },
      });

      const originalIsFeatureEnabled = systemConfigService.isFeatureEnabled;
      systemConfigService.isFeatureEnabled = async (key: string) => {
        if (key === FEATURE_FLAGS.WEBHOOKS_ENABLED) return false;
        return true;
      };

      try {
        const testPingRes = await requestApi(
          "POST",
          `/api/v1/integration/webhooks/${webhook.id}/test`,
        );
        assert.strictEqual(testPingRes.status, 403);
        assert.strictEqual(testPingRes.body.code, ERROR_CODE.FEATURE_DISABLED);

        const retryRes = await requestApi(
          "POST",
          `/api/v1/integration/webhooks/deliveries/${delivery.id}/retry`,
        );
        assert.strictEqual(retryRes.status, 403);
        assert.strictEqual(retryRes.body.code, ERROR_CODE.FEATURE_DISABLED);
      } finally {
        systemConfigService.isFeatureEnabled = originalIsFeatureEnabled;
      }
    });
  });
});
