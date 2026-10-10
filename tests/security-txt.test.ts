import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import app from "../src/app";
import {
  SECURITY_TXT_PATHS,
  SECURITY_TXT_DEFAULTS,
} from "../src/common/constants/security-txt.constant";
import {
  SecurityTxtService,
  securityTxtService,
} from "../src/modules/security-txt/security-txt.service";
import { swaggerSpec } from "../src/config/swagger.config";

describe("RFC 9116 Security.txt Test Suite", () => {
  describe("1. Constants & Default Settings", () => {
    it("should export correct well-known and legacy paths", () => {
      assert.equal(SECURITY_TXT_PATHS.WELL_KNOWN, "/.well-known/security.txt");
      assert.equal(SECURITY_TXT_PATHS.LEGACY, "/security.txt");
    });

    it("should define RFC 9116 default values", () => {
      assert.equal(SECURITY_TXT_DEFAULTS.CONTACT_EMAIL, "security@example.com");
      assert.equal(SECURITY_TXT_DEFAULTS.PREFERRED_LANGUAGES, "en, vi");
      assert.equal(SECURITY_TXT_DEFAULTS.EXPIRY_DAYS, 365);
    });
  });

  describe("2. SecurityTxtService Unit Tests", () => {
    it("should generate RFC 9116 compliant content with mandatory fields", () => {
      const content = securityTxtService.generateSecurityTxt();

      // RFC 9116: Contact is mandatory
      assert.match(content, /^Contact:\s+(mailto:|https:\/\/).+$/m);

      // RFC 9116: Expires is mandatory
      assert.match(content, /^Expires:\s+\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/m);

      // RFC 9116: Canonical & Preferred-Languages
      assert.match(content, /^Preferred-Languages:\s+en, vi$/m);
      assert.match(
        content,
        /^Canonical:\s+https?:\/\/.+\/\.well-known\/security\.txt$/m,
      );

      // Policy directive
      assert.match(content, /^Policy:\s+https?:\/\/.+$/m);
    });

    it("should enforce Expires date to be within 1 year in the future", () => {
      const content = securityTxtService.generateSecurityTxt();
      const expiresMatch = content.match(/^Expires:\s+(.+)$/m);
      assert.ok(expiresMatch, "Expires field must exist");

      const expiresDate = new Date(expiresMatch[1]);
      const now = new Date();
      const oneYearAndOneDayFromNow = new Date(
        now.getTime() + 366 * 24 * 60 * 60 * 1000,
      );

      assert.ok(
        expiresDate.getTime() > now.getTime(),
        "Expires date must be in the future",
      );
      assert.ok(
        expiresDate.getTime() <= oneYearAndOneDayFromNow.getTime(),
        "Expires date must not exceed 1 year in the future (RFC 9116 Section 2.5.5)",
      );
    });

    it("should format mailto: URI correctly when only plain email is provided", () => {
      const service = new SecurityTxtService();
      const content = service.generateSecurityTxt({
        contactEmail: "admin@mycompany.org",
      });

      assert.match(content, /^Contact:\s+mailto:admin@mycompany\.org$/m);
    });

    it("should preserve web URL when contact is an HTTPS disclosure form", () => {
      const service = new SecurityTxtService();
      const content = service.generateSecurityTxt({
        contactEmail: "https://mycompany.org/security/report",
      });

      assert.match(
        content,
        /^Contact:\s+https:\/\/mycompany\.org\/security\/report$/m,
      );
    });

    it("should include Policy and Acknowledgments when specified", () => {
      const service = new SecurityTxtService();
      const content = service.generateSecurityTxt({
        policyUrl: "https://mycompany.org/disclosure-policy",
        acknowledgmentsUrl: "https://mycompany.org/security/hall-of-fame",
      });

      assert.match(
        content,
        /^Policy:\s+https:\/\/mycompany\.org\/disclosure-policy$/m,
      );
      assert.match(
        content,
        /^Acknowledgments:\s+https:\/\/mycompany\.org\/security\/hall-of-fame$/m,
      );
    });
  });

  describe("3. HTTP Integration Tests (Live Express App)", () => {
    let server: http.Server;
    let baseUrl: string;

    beforeEach(async () => {
      server = http.createServer(app);
      await new Promise<void>((resolve) => server.listen(0, resolve));
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      baseUrl = `http://127.0.0.1:${port}`;
    });

    afterEach(async () => {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    });

    it("GET /.well-known/security.txt should return HTTP 200 with text/plain charset=utf-8", async () => {
      const res = await fetch(`${baseUrl}/.well-known/security.txt`);
      assert.equal(res.status, 200);

      const contentType = res.headers.get("content-type");
      assert.ok(
        contentType?.includes("text/plain"),
        `Expected text/plain, got: ${contentType}`,
      );
      assert.ok(
        contentType?.includes("charset=utf-8"),
        `Expected charset=utf-8, got: ${contentType}`,
      );

      const cacheControl = res.headers.get("cache-control");
      assert.ok(cacheControl?.includes("public"));

      const body = await res.text();
      assert.match(body, /^Contact:\s+mailto:/m);
      assert.match(body, /^Expires:\s+/m);
      assert.match(body, /^Preferred-Languages:\s+en, vi/m);
      assert.match(body, /^Canonical:\s+.+\/\.well-known\/security\.txt/m);
    });

    it("GET /security.txt should redirect 301 to /.well-known/security.txt", async () => {
      const res = await fetch(`${baseUrl}/security.txt`, {
        redirect: "manual",
      });

      assert.equal(res.status, 301);
      assert.equal(res.headers.get("location"), SECURITY_TXT_PATHS.WELL_KNOWN);
    });

    it("GET /api/v1/.well-known/security.txt should also serve security.txt under API prefix", async () => {
      const res = await fetch(`${baseUrl}/api/v1/.well-known/security.txt`);
      assert.equal(res.status, 200);
      const body = await res.text();
      assert.match(body, /^Contact:\s+/m);
    });

    it("GET /api/v1/security.txt should redirect 301 to /.well-known/security.txt", async () => {
      const res = await fetch(`${baseUrl}/api/v1/security.txt`, {
        redirect: "manual",
      });
      assert.equal(res.status, 301);
      assert.equal(res.headers.get("location"), SECURITY_TXT_PATHS.WELL_KNOWN);
    });
  });

  describe("4. OpenAPI Swagger Specification", () => {
    it("should document /.well-known/security.txt and /security.txt in Swagger spec", () => {
      assert.ok(
        swaggerSpec.paths["/.well-known/security.txt"],
        "Swagger must document /.well-known/security.txt",
      );
      assert.ok(
        swaggerSpec.paths["/security.txt"],
        "Swagger must document /security.txt",
      );

      const wellKnownGet = swaggerSpec.paths["/.well-known/security.txt"].get;
      assert.equal(wellKnownGet.tags[0], "Security");
      assert.ok(wellKnownGet.responses["200"]);

      const legacyGet = swaggerSpec.paths["/security.txt"].get;
      assert.equal(legacyGet.tags[0], "Security");
      assert.ok(legacyGet.responses["301"]);
    });
  });
});
