import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  TURNSTILE_VERIFY_URL,
  TURNSTILE_DUMMY_SECRET_PASS,
  TURNSTILE_DUMMY_SECRET_FAIL,
  TURNSTILE_DUMMY_SECRET_SPENT,
  TURNSTILE_HEADERS,
  TURNSTILE_BODY_KEY,
  TURNSTILE_ACTION,
} from "../src/common/constants/turnstile.constant";
import { ERROR_CODE } from "../src/common/errors/error-code";
import { AppError } from "../src/common/errors/app-error";
import {
  TurnstileService,
  TurnstileVerifyResponse,
} from "../src/common/services/turnstile.service";
import {
  extractTurnstileToken,
  turnstileGuard,
} from "../src/middlewares/turnstile.middleware";
import {
  registerSchema,
  forgotPasswordSchema,
  resendVerificationSchema,
} from "../src/modules/auth/auth.validation";

describe("Cloudflare Turnstile Anti-Bot & Captcha Test Suite", () => {
  describe("1. Constants & Error Codes Integrity", () => {
    it("should export correct Cloudflare siteverify endpoint", () => {
      assert.equal(
        TURNSTILE_VERIFY_URL,
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      );
    });

    it("should export official Cloudflare testing dummy secrets", () => {
      assert.equal(
        TURNSTILE_DUMMY_SECRET_PASS,
        "1x0000000000000000000000000000000AA",
      );
      assert.equal(
        TURNSTILE_DUMMY_SECRET_FAIL,
        "2x0000000000000000000000000000000AA",
      );
      assert.equal(
        TURNSTILE_DUMMY_SECRET_SPENT,
        "3x0000000000000000000000000000000AA",
      );
    });

    it("should export header and body keys adhering to conventions", () => {
      assert.equal(TURNSTILE_HEADERS.RESPONSE, "cf-turnstile-response");
      assert.equal(TURNSTILE_HEADERS.TOKEN, "x-turnstile-token");
      assert.equal(TURNSTILE_BODY_KEY, "turnstileToken");
      assert.equal(TURNSTILE_ACTION.REGISTER, "register");
      assert.equal(TURNSTILE_ACTION.FORGOT_PASSWORD, "forgot_password");
      assert.equal(TURNSTILE_ACTION.RESEND_VERIFICATION, "resend_verification");
    });

    it("should define CAPTCHA error codes in ERROR_CODE constant", () => {
      assert.equal(ERROR_CODE.CAPTCHA_REQUIRED, "CAPTCHA_REQUIRED");
      assert.equal(ERROR_CODE.CAPTCHA_INVALID, "CAPTCHA_INVALID");
    });
  });

  describe("2. TurnstileService Verification Logic", () => {
    it("should automatically bypass and return isValid: true when disabled", async () => {
      const service = new TurnstileService({ enabled: false });
      const result = await service.verifyToken(undefined);
      assert.equal(result.isValid, true);

      const resultWithEmpty = await service.verifyToken("");
      assert.equal(resultWithEmpty.isValid, true);
    });

    it("should return error CAPTCHA_REQUIRED when enabled but token is missing", async () => {
      const service = new TurnstileService({
        enabled: true,
        secretKey: "dummy_key",
      });

      const resNull = await service.verifyToken(null);
      assert.equal(resNull.isValid, false);
      assert.equal(resNull.error, "CAPTCHA_REQUIRED");

      const resEmpty = await service.verifyToken("   ");
      assert.equal(resEmpty.isValid, false);
      assert.equal(resEmpty.error, "CAPTCHA_REQUIRED");
    });

    it("should verify successfully when Cloudflare returns success: true", async () => {
      const mockResponse: TurnstileVerifyResponse = {
        success: true,
        challenge_ts: "2026-10-01T00:00:00Z",
        hostname: "myapp.com",
        action: "register",
      };

      let capturedBody: string = "";
      const customFetcher = async (_url: any, init?: RequestInit) => {
        capturedBody = init?.body as string;
        return {
          ok: true,
          json: async () => mockResponse,
        } as Response;
      };

      const service = new TurnstileService({
        enabled: true,
        secretKey: "test_secret_key",
      });

      const result = await service.verifyToken(
        "valid_client_token",
        {
          remoteIp: "203.0.113.1",
          action: "register",
          idempotencyKey: "test-uuid-1234",
        },
        customFetcher,
      );

      assert.equal(result.isValid, true);
      assert.equal(result.hostname, "myapp.com");
      assert.equal(result.action, "register");

      const params = new URLSearchParams(capturedBody);
      assert.equal(params.get("secret"), "test_secret_key");
      assert.equal(params.get("response"), "valid_client_token");
      assert.equal(params.get("remoteip"), "203.0.113.1");
      assert.equal(params.get("idempotency_key"), "test-uuid-1234");
    });

    it("should return CAPTCHA_INVALID when Cloudflare returns success: false", async () => {
      const mockResponse: TurnstileVerifyResponse = {
        success: false,
        "error-codes": ["invalid-input-response"],
      };

      const customFetcher = async () =>
        ({
          ok: true,
          json: async () => mockResponse,
        }) as Response;

      const service = new TurnstileService({
        enabled: true,
        secretKey: "test_secret",
      });

      const result = await service.verifyToken(
        "invalid_token",
        {},
        customFetcher,
      );

      assert.equal(result.isValid, false);
      assert.equal(result.error, "CAPTCHA_INVALID");
      assert.deepEqual(result.errorCodes, ["invalid-input-response"]);
    });

    it("should reject when action mismatch is detected", async () => {
      const mockResponse: TurnstileVerifyResponse = {
        success: true,
        action: "login",
      };

      const customFetcher = async () =>
        ({
          ok: true,
          json: async () => mockResponse,
        }) as Response;

      const service = new TurnstileService({
        enabled: true,
        secretKey: "test_secret",
      });

      const result = await service.verifyToken(
        "valid_token",
        { action: "register" },
        customFetcher,
      );

      assert.equal(result.isValid, false);
      assert.equal(result.error, "CAPTCHA_ACTION_MISMATCH");
    });

    it("should handle HTTP error responses from Cloudflare gracefully", async () => {
      const customFetcher = async () =>
        ({
          ok: false,
          status: 500,
        }) as Response;

      const service = new TurnstileService({
        enabled: true,
        secretKey: "test_secret",
      });

      const result = await service.verifyToken("token", {}, customFetcher);
      assert.equal(result.isValid, false);
      assert.equal(result.error, "CAPTCHA_SERVICE_UNAVAILABLE");
    });

    it("should handle network exceptions / timeouts gracefully", async () => {
      const customFetcher = async () => {
        throw new Error("Network unreachable");
      };

      const service = new TurnstileService({
        enabled: true,
        secretKey: "test_secret",
      });

      const result = await service.verifyToken("token", {}, customFetcher);
      assert.equal(result.isValid, false);
      assert.equal(result.error, "CAPTCHA_NETWORK_ERROR");
    });
  });

  describe("3. Turnstile Middleware & Token Extraction", () => {
    it("should extract token from cf-turnstile-response header", () => {
      const req: any = {
        headers: { "cf-turnstile-response": "header_token_123" },
      };
      assert.equal(extractTurnstileToken(req), "header_token_123");
    });

    it("should extract token from x-turnstile-token header", () => {
      const req: any = {
        headers: { "x-turnstile-token": "alt_header_token" },
      };
      assert.equal(extractTurnstileToken(req), "alt_header_token");
    });

    it("should extract token from body turnstileToken field", () => {
      const req: any = {
        headers: {},
        body: { turnstileToken: "body_token_456" },
      };
      assert.equal(extractTurnstileToken(req), "body_token_456");
    });

    it("should extract token from body cf-turnstile-response field", () => {
      const req: any = {
        headers: {},
        body: { "cf-turnstile-response": "body_alt_token_789" },
      };
      assert.equal(extractTurnstileToken(req), "body_alt_token_789");
    });

    it("should return undefined when no token is present in request", () => {
      const req: any = { headers: {}, body: {} };
      assert.equal(extractTurnstileToken(req), undefined);
    });

    it("turnstileGuard should pass through without error when service is disabled", async () => {
      const disabledService = new TurnstileService({ enabled: false });
      const middleware = turnstileGuard({ service: disabledService });

      let nextCalled = false;
      let passedError: any = null;

      const req: any = { headers: {}, body: {} };
      await middleware(req, {} as any, (err?: any) => {
        nextCalled = true;
        passedError = err;
      });

      assert.equal(nextCalled, true);
      assert.equal(passedError, undefined);
    });

    it("turnstileGuard should reject with CAPTCHA_REQUIRED when enabled and token missing", async () => {
      const enabledService = new TurnstileService({
        enabled: true,
        secretKey: "sec",
      });
      const middleware = turnstileGuard({ service: enabledService });

      let passedError: any = null;
      const req: any = { headers: {}, body: {} };

      await middleware(req, {} as any, (err?: any) => {
        passedError = err;
      });

      assert.ok(passedError instanceof AppError);
      assert.equal(passedError.statusCode, 400);
      assert.equal(passedError.code, ERROR_CODE.CAPTCHA_REQUIRED);
    });

    it("turnstileGuard should reject with CAPTCHA_INVALID when verification fails", async () => {
      const mockFailService = new TurnstileService({
        enabled: true,
        secretKey: "sec",
      });
      // Mock verifyToken
      mockFailService.verifyToken = async () => ({
        isValid: false,
        error: "CAPTCHA_INVALID",
      });

      const middleware = turnstileGuard({ service: mockFailService });

      let passedError: any = null;
      const req: any = {
        headers: { "cf-turnstile-response": "bad_token" },
        body: {},
      };

      await middleware(req, {} as any, (err?: any) => {
        passedError = err;
      });

      assert.ok(passedError instanceof AppError);
      assert.equal(passedError.statusCode, 400);
      assert.equal(passedError.code, ERROR_CODE.CAPTCHA_INVALID);
    });

    it("turnstileGuard should call next() without error when verification succeeds", async () => {
      const mockSuccessService = new TurnstileService({
        enabled: true,
        secretKey: "sec",
      });
      mockSuccessService.verifyToken = async () => ({ isValid: true });

      const middleware = turnstileGuard({ service: mockSuccessService });

      let nextCalled = false;
      let passedError: any = null;
      const req: any = {
        headers: { "cf-turnstile-response": "good_token" },
        body: {},
      };

      await middleware(req, {} as any, (err?: any) => {
        nextCalled = true;
        passedError = err;
      });

      assert.equal(nextCalled, true);
      assert.equal(passedError, undefined);
    });
  });

  describe("4. Auth Validation Schemas Turnstile Compatibility", () => {
    it("registerSchema should validate payload with or without turnstileToken", () => {
      const basePayload = {
        email: "test@example.com",
        password: "Password123!",
        fullName: "Test User",
      };

      const withoutToken = registerSchema.safeParse(basePayload);
      assert.equal(withoutToken.success, true);

      const withToken = registerSchema.safeParse({
        ...basePayload,
        turnstileToken: "cf-token-abc-xyz",
      });
      assert.equal(withToken.success, true);
      if (withToken.success) {
        assert.equal(withToken.data.turnstileToken, "cf-token-abc-xyz");
      }
    });

    it("forgotPasswordSchema should validate payload with or without turnstileToken", () => {
      const withoutToken = forgotPasswordSchema.safeParse({
        email: "forgot@example.com",
      });
      assert.equal(withoutToken.success, true);

      const withToken = forgotPasswordSchema.safeParse({
        email: "forgot@example.com",
        turnstileToken: "cf-token-123",
      });
      assert.equal(withToken.success, true);
      if (withToken.success) {
        assert.equal(withToken.data.turnstileToken, "cf-token-123");
      }
    });

    it("resendVerificationSchema should validate payload with or without turnstileToken", () => {
      const withoutToken = resendVerificationSchema.safeParse({
        email: "resend@example.com",
      });
      assert.equal(withoutToken.success, true);

      const withToken = resendVerificationSchema.safeParse({
        email: "resend@example.com",
        turnstileToken: "cf-token-456",
      });
      assert.equal(withToken.success, true);
      if (withToken.success) {
        assert.equal(withToken.data.turnstileToken, "cf-token-456");
      }
    });
  });
});
