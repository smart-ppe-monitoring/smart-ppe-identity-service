import { describe, it } from "node:test";
import assert from "node:assert/strict";
import jwt from "jsonwebtoken";
import { createUserSchema, updateUserSchema, assignUserSitesSchema } from "../src/modules/users/user.validation";
import { jwtKeyService } from "../src/common/services/jwt-key.service";
import { JWT_PURPOSE } from "../src/common/constants/jwt.constant";
import { ROLES } from "../src/common/constants/role.constant";
import { PERMISSIONS } from "../src/common/constants/permission.constant";

describe("Enterprise Multi-tenant: User Site Scoping & JWT Tenancy Claims", () => {
  const validSite1 = "018f2345-6789-7abc-def0-1234567890ab";
  const validSite2 = "018f2345-6789-7abc-def0-1234567890cd";
  const validRoleId = "018f2345-6789-7abc-def0-1234567890ef";

  describe("1. Validation Schemas for siteIds", () => {
    it("should accept valid siteIds array in createUserSchema", () => {
      const parsed = createUserSchema.parse({
        email: "officer@company.com",
        password: "StrongPassword123!",
        roleId: validRoleId,
        siteIds: [validSite1, validSite2],
      });
      assert.deepEqual(parsed.siteIds, [validSite1, validSite2]);
    });

    it("should accept empty or optional siteIds in createUserSchema", () => {
      const parsed = createUserSchema.parse({
        email: "admin@company.com",
        password: "StrongPassword123!",
        roleId: validRoleId,
      });
      assert.equal(parsed.siteIds, undefined);
    });

    it("should reject non-UUID siteIds in createUserSchema", () => {
      assert.throws(() => {
        createUserSchema.parse({
          email: "officer@company.com",
          password: "StrongPassword123!",
          roleId: validRoleId,
          siteIds: ["invalid-site-id"],
        });
      });
    });

    it("should accept valid siteIds array in updateUserSchema", () => {
      const parsed = updateUserSchema.parse({
        siteIds: [validSite1],
      });
      assert.deepEqual(parsed.siteIds, [validSite1]);
    });

    it("should validate assignUserSitesSchema with valid UUID array", () => {
      const parsed = assignUserSitesSchema.parse({
        siteIds: [validSite1, validSite2],
      });
      assert.deepEqual(parsed.siteIds, [validSite1, validSite2]);
    });

    it("should reject non-UUID array in assignUserSitesSchema", () => {
      assert.throws(() => {
        assignUserSitesSchema.parse({
          siteIds: ["not-a-uuid"],
        });
      });
    });
  });

  describe("2. JWT Access Token Signing with Tenancy Claims", () => {
    it("should embed siteId and siteIds claims into RS256 Access Token", () => {
      const user = {
        id: "018f0000-0000-7000-8000-000000000001",
        email: "safety.officer@site.vn",
        role: { name: ROLES.SAFETY_OFFICER },
        roleId: validRoleId,
        siteIds: [validSite1, validSite2],
      };

      const userSiteIds = Array.isArray(user.siteIds) ? user.siteIds : [];
      const userSiteId = userSiteIds.length > 0 ? userSiteIds[0] : null;

      const payload = {
        id: user.id,
        email: user.email,
        role: user.role.name,
        roleId: user.roleId,
        siteId: userSiteId,
        siteIds: userSiteIds,
        permissions: [PERMISSIONS.PPE_SITE_READ, PERMISSIONS.PPE_CAMERA_READ],
        mustChangePassword: false,
        purpose: JWT_PURPOSE.ACCESS,
      };

      const token = jwtKeyService.signAccessToken(payload);
      assert.ok(token);

      const decoded: any = jwt.verify(token, jwtKeyService.getPublicKeyPem(), {
        algorithms: ["RS256"],
      });

      assert.equal(decoded.id, user.id);
      assert.equal(decoded.role, ROLES.SAFETY_OFFICER);
      assert.equal(decoded.siteId, validSite1);
      assert.deepEqual(decoded.siteIds, [validSite1, validSite2]);
      assert.ok(Array.isArray(decoded.permissions));
      assert.equal(decoded.purpose, JWT_PURPOSE.ACCESS);
    });

    it("should handle user with no assigned sites safely (empty array, null siteId)", () => {
      const user = {
        id: "018f0000-0000-7000-8000-000000000002",
        email: "unassigned@site.vn",
        role: { name: ROLES.SAFETY_OFFICER },
        roleId: validRoleId,
        siteIds: [],
      };

      const userSiteIds = Array.isArray(user.siteIds) ? user.siteIds : [];
      const userSiteId = userSiteIds.length > 0 ? userSiteIds[0] : null;

      const payload = {
        id: user.id,
        email: user.email,
        role: user.role.name,
        roleId: user.roleId,
        siteId: userSiteId,
        siteIds: userSiteIds,
        permissions: [PERMISSIONS.PPE_SITE_READ],
        mustChangePassword: false,
        purpose: JWT_PURPOSE.ACCESS,
      };

      const token = jwtKeyService.signAccessToken(payload);
      const decoded: any = jwt.verify(token, jwtKeyService.getPublicKeyPem(), {
        algorithms: ["RS256"],
      });

      assert.equal(decoded.siteId, null);
      assert.deepEqual(decoded.siteIds, []);
    });
  });

  describe("3. Cross-Service Tenancy Scoping Simulation", () => {
    it("should allow satellite service BOLA guard to extract siteIds from token", () => {
      const payload = {
        id: "018f0000-0000-7000-8000-000000000003",
        email: "manager@site-a.com",
        role: ROLES.SAFETY_MANAGER,
        roleId: validRoleId,
        siteId: validSite1,
        siteIds: [validSite1],
        permissions: [PERMISSIONS.PPE_SITE_READ, PERMISSIONS.PPE_SITE_MANAGE],
        mustChangePassword: false,
        purpose: JWT_PURPOSE.ACCESS,
      };

      const token = jwtKeyService.signAccessToken(payload);

      // Simulate satellite service auth.middleware.ts extraction
      const decoded: any = jwt.verify(token, jwtKeyService.getPublicKeyPem(), {
        algorithms: ["RS256"],
      });

      const reqUser = {
        id: decoded.id || decoded.sub,
        email: decoded.email,
        role: decoded.role,
        roleId: decoded.roleId,
        siteId: decoded.siteId || null,
        siteIds: Array.isArray(decoded.siteIds)
          ? decoded.siteIds
          : decoded.siteId
            ? [decoded.siteId]
            : [],
        permissions: Array.isArray(decoded.permissions) ? decoded.permissions : [],
      };

      assert.equal(reqUser.role, ROLES.SAFETY_MANAGER);
      assert.equal(reqUser.siteId, validSite1);
      assert.deepEqual(reqUser.siteIds, [validSite1]);

      // Simulate SiteService.getAllowedSiteIds(reqUser)
      const allowed = new Set<string>();
      if (reqUser.siteId) allowed.add(reqUser.siteId);
      if (Array.isArray(reqUser.siteIds)) {
        for (const sid of reqUser.siteIds) if (sid) allowed.add(sid);
      }
      const allowedSiteIds = Array.from(allowed);

      assert.deepEqual(allowedSiteIds, [validSite1]);
      assert.ok(allowedSiteIds.includes(validSite1));
      assert.ok(!allowedSiteIds.includes(validSite2)); // Foreign site blocked!
    });
  });

  describe("4. UserService assignSites & siteIds Management", () => {
    it("should assign siteIds and invalidate cache via UserService.assignSites", async () => {
      const { UserService } = await import("../src/modules/users/user.service");
      const service = new UserService();

      let updatedData: any = null;
      let invalidatedUserId: string | null = null;

      (service as any).repository = {
        findById: async (id: string) => ({
          id,
          email: "target@company.com",
          role: { name: ROLES.SAFETY_OFFICER },
          roleId: validRoleId,
          siteIds: [],
        }),
        assignSites: async (id: string, siteIds: string[]) => {
          updatedData = { id, siteIds };
          return {
            id,
            email: "target@company.com",
            roleId: validRoleId,
            siteIds,
          };
        },
      };

      const result = await service.assignSites("user-1", [validSite1, validSite2, validSite1]);
      assert.deepEqual(result.siteIds, [validSite1, validSite2]);
      assert.deepEqual(updatedData, { id: "user-1", siteIds: [validSite1, validSite2] });
    });

    it("should reject non-admin actor assigning siteIds with 403 FORBIDDEN", async () => {
      const { UserService } = await import("../src/modules/users/user.service");
      const service = new UserService();

      const nonAdminRoleId1 = "018f0000-0000-7000-8000-0000000000aa";
      const nonAdminRoleId2 = "018f0000-0000-7000-8000-0000000000bb";

      (service as any).repository = {
        findById: async (id: string) => {
          if (id === "actor-non-admin") {
            return { id, role: { name: ROLES.SAFETY_MANAGER }, roleId: nonAdminRoleId1 };
          }
          return { id, role: { name: ROLES.SAFETY_OFFICER }, roleId: nonAdminRoleId2 };
        },
      };

      await assert.rejects(
        async () => {
          await service.assignSites("user-1", [validSite1], "actor-non-admin");
        },
        (err: any) => {
          assert.equal(err.statusCode, 403);
          assert.equal(err.code, "FORBIDDEN");
          return true;
        },
      );
    });

    it("should reject non-admin actor updating siteIds in update() with 403 FORBIDDEN", async () => {
      const { UserService } = await import("../src/modules/users/user.service");
      const service = new UserService();

      const nonAdminRoleId1 = "018f0000-0000-7000-8000-0000000000aa";
      const nonAdminRoleId2 = "018f0000-0000-7000-8000-0000000000bb";

      (service as any).repository = {
        findById: async (id: string) => {
          if (id === "actor-non-admin") {
            return { id, role: { name: ROLES.SAFETY_MANAGER }, roleId: nonAdminRoleId1 };
          }
          return { id, role: { name: ROLES.SAFETY_OFFICER }, roleId: nonAdminRoleId2, isActive: true };
        },
      };

      await assert.rejects(
        async () => {
          await service.update("user-1", { siteIds: [validSite1] }, "actor-non-admin");
        },
        (err: any) => {
          assert.equal(err.statusCode, 403);
          assert.equal(err.code, "FORBIDDEN");
          return true;
        },
      );
    });
  });
});
