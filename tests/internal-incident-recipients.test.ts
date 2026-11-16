import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createRequireInternalServiceToken } from "../src/middlewares/internal-auth.middleware";
import { internalIncidentRecipientsQuerySchema } from "../src/modules/users/user.validation";
import { UserService } from "../src/modules/users/user.service";
import { UserRepository } from "../src/modules/users/user.repository";
import userRoute from "../src/modules/users/user.route";
import { ERROR_CODE } from "../src/common/errors/error-code";
import { GATEWAY_HEADERS } from "../src/common/constants/gateway.constant";

describe("Internal Incident Notification Recipients API (M2M)", () => {
  describe("requireInternalServiceToken middleware", () => {
    it("should fail closed with 503 when INTERNAL_SERVICE_TOKEN is unconfigured", () => {
      const middleware = createRequireInternalServiceToken("");
      let capturedErr: any;
      middleware({ headers: {} } as any, {} as any, (err?: any) => {
        capturedErr = err;
      });
      assert.strictEqual(capturedErr?.statusCode, 503);
      assert.strictEqual(capturedErr?.code, ERROR_CODE.SERVICE_UNAVAILABLE);
    });

    it("should return 401 when internal service token is missing", () => {
      const middleware = createRequireInternalServiceToken("super-secret-m2m-token");
      let capturedErr: any;
      middleware({ headers: {} } as any, {} as any, (err?: any) => {
        capturedErr = err;
      });
      assert.strictEqual(capturedErr?.statusCode, 401);
      assert.strictEqual(capturedErr?.code, ERROR_CODE.UNAUTHORIZED);
    });

    it("should return 403 when internal service token is invalid", () => {
      const middleware = createRequireInternalServiceToken("super-secret-m2m-token");
      let capturedErr: any;
      middleware(
        { headers: { [GATEWAY_HEADERS.INTERNAL_SERVICE_TOKEN]: "wrong-token" } } as any,
        {} as any,
        (err?: any) => {
          capturedErr = err;
        },
      );
      assert.strictEqual(capturedErr?.statusCode, 403);
      assert.strictEqual(capturedErr?.code, ERROR_CODE.FORBIDDEN);
    });

    it("should pass when valid x-internal-service-token header is provided", () => {
      const middleware = createRequireInternalServiceToken("super-secret-m2m-token");
      let capturedErr: any = "not-called";
      middleware(
        { headers: { [GATEWAY_HEADERS.INTERNAL_SERVICE_TOKEN]: "super-secret-m2m-token" } } as any,
        {} as any,
        (err?: any) => {
          capturedErr = err;
        },
      );
      assert.strictEqual(capturedErr, undefined);
    });
  });

  describe("internalIncidentRecipientsQuerySchema", () => {
    it("should accept omitted siteId or valid UUIDv7 siteId and reject invalid values", () => {
      assert.deepStrictEqual(internalIncidentRecipientsQuerySchema.parse({}), {});

      const validSiteId = "018f2345-6789-7abc-def0-1234567890ab";
      assert.deepStrictEqual(
        internalIncidentRecipientsQuerySchema.parse({ siteId: validSiteId }),
        { siteId: validSiteId },
      );

      assert.throws(() => {
        internalIncidentRecipientsQuerySchema.parse({ siteId: "not-a-uuid" });
      });
    });
  });

  describe("Route ordering & Service/Repository delegation", () => {
    it("must register GET /internal/incident-recipients BEFORE /:id param route", () => {
      const getPaths = (userRoute.stack || [])
        .filter((layer: any) => layer.route?.methods?.get)
        .map((layer: any) => layer.route.path);

      const internalIdx = getPaths.indexOf("/internal/incident-recipients");
      const idIdx = getPaths.indexOf("/:id");
      assert.ok(internalIdx !== -1, "GET /internal/incident-recipients route must exist");
      assert.ok(idIdx !== -1, "GET /:id route must exist");
      assert.ok(
        internalIdx < idIdx,
        `GET /internal/incident-recipients (${internalIdx}) must precede /:id (${idIdx})`,
      );
    });

    it("UserService.findIncidentNotificationRecipients delegates to repository with siteId", async () => {
      const siteId = "018f2345-6789-7abc-def0-1234567890ab";
      const expected = [
        {
          id: "018f2345-6789-7abc-def0-123456789001",
          email: "officer@ppe.local",
          fullName: "Safety Officer",
          role: "SAFETY_OFFICER",
        },
      ];
      const fakeRepo = {
        findIncidentNotificationRecipients: async (sid?: string) => {
          assert.strictEqual(sid, siteId);
          return expected;
        },
      } as unknown as UserRepository;

      const service = new UserService(fakeRepo);
      const res = await service.findIncidentNotificationRecipients(siteId);
      assert.deepStrictEqual(res, expected);
    });

    it("UserRepository.findIncidentNotificationRecipients queries active non-deleted users with site filter", async () => {
      let capturedArgs: any;
      const fakeDb = {
        user: {
          findMany: async (args: any) => {
            capturedArgs = args;
            return [
              {
                id: "018f2345-6789-7abc-def0-123456789002",
                email: "admin@ppe.local",
                fullName: "Admin",
                role: { name: "ADMIN" },
              },
            ];
          },
        },
      } as any;

      const repo = new UserRepository(fakeDb);
      const siteId = "018f2345-6789-7abc-def0-1234567890ab";
      const rows = await repo.findIncidentNotificationRecipients(siteId);

      assert.strictEqual(capturedArgs.where.isActive, true);
      assert.strictEqual(capturedArgs.where.deletedAt, null);
      const jsonWhere = JSON.stringify(capturedArgs.where);
      assert.ok(jsonWhere.includes(siteId));
      assert.ok(jsonWhere.includes("ADMIN"));
      assert.ok(jsonWhere.includes("SAFETY_OFFICER"));
      assert.ok(
        !jsonWhere.includes('"equals":[]'),
        "Unassigned siteIds: [] users MUST NOT match arbitrary siteId",
      );
      assert.deepStrictEqual(rows, [
        {
          id: "018f2345-6789-7abc-def0-123456789002",
          email: "admin@ppe.local",
          fullName: "Admin",
          role: "ADMIN",
        },
      ]);

      // When siteId is omitted, restrict strictly to ADMIN only
      await repo.findIncidentNotificationRecipients(undefined);
      const noSiteWhere = JSON.stringify(capturedArgs.where);
      assert.ok(noSiteWhere.includes("ADMIN"));
      assert.ok(!noSiteWhere.includes("SAFETY_OFFICER"));
    });
  });
});
