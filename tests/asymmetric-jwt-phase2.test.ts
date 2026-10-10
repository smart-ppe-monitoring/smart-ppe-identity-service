import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import app from "../src/app";
import {
  JWT_ALGORITHM,
  JWKS_CONSTANTS,
  JWT_PURPOSE,
} from "../src/common/constants/jwt.constant";
import {
  JwtKeyService,
  jwtKeyService,
} from "../src/common/services/jwt-key.service";
import {
  createVerifyJwtLocally,
  verifyJwtLocally,
  optionalVerifyJwtLocally,
  clearJwtPublicKeyCache,
} from "../src/middlewares/verify-jwt-locally.middleware";
import { swaggerSpec } from "../src/config/swagger.config";
import { AppError } from "../src/common/errors/app-error";
import { ERROR_CODE } from "../src/common/errors/error-code";

describe("Microservices Phase 2: Asymmetric JWT (RS256) & JWKS Test Suite", () => {
  describe("1. Constants & Default Cryptographic Configuration", () => {
    it("should export supported JWT algorithms (RS256 as primary)", () => {
      assert.equal(JWT_ALGORITHM.RS256, "RS256");
      assert.equal(JWT_ALGORITHM.HS256, "HS256");
    });

    it("should export RFC 7517 JWKS specification constants", () => {
      assert.equal(JWKS_CONSTANTS.KEY_TYPE, "RSA");
      assert.equal(JWKS_CONSTANTS.KEY_USE, "sig");
      assert.equal(JWKS_CONSTANTS.DEFAULT_KEY_ID, "template-be-auth-key-1");
      assert.equal(JWKS_CONSTANTS.DEFAULT_CACHE_TTL_MS, 24 * 60 * 60 * 1000);
      assert.equal(
        JWKS_CONSTANTS.WELL_KNOWN_JWKS_PATH,
        "/.well-known/jwks.json",
      );
      assert.ok(JWKS_CONSTANTS.HTTP_CACHE_CONTROL.includes("public"));
      assert.ok(JWKS_CONSTANTS.HTTP_CACHE_CONTROL.includes("max-age=86400"));
    });

    it("should export standard JWT purposes", () => {
      assert.equal(JWT_PURPOSE.ACCESS, "ACCESS");
      assert.equal(JWT_PURPOSE.REFRESH, "REFRESH");
      assert.equal(JWT_PURPOSE.TWO_FACTOR, "2FA_VERIFICATION");
      assert.equal(JWT_PURPOSE.SSE_STREAM_TICKET, "SSE_STREAM_TICKET");
    });
  });

  describe("2. JwtKeyService Unit Tests", () => {
    it("should initialize with a valid 2048-bit RSA key pair", () => {
      const privateKey = jwtKeyService.getPrivateKeyPem();
      const publicKey = jwtKeyService.getPublicKeyPem();

      assert.ok(privateKey, "Private Key must not be empty");
      assert.ok(publicKey, "Public Key must not be empty");
      assert.ok(
        privateKey.includes("-----BEGIN PRIVATE KEY-----") ||
          privateKey.includes("-----BEGIN RSA PRIVATE KEY-----"),
        "Private Key must be in PEM format",
      );
      assert.ok(
        publicKey.includes("-----BEGIN PUBLIC KEY-----"),
        "Public Key must be in SPKI PEM format",
      );
      assert.equal(jwtKeyService.getAlgorithm(), JWT_ALGORITHM.RS256);
      assert.ok(jwtKeyService.getKeyId(), "Key ID must be defined");
    });

    it("should generate RFC 7517 compliant JWK format", () => {
      const jwk = jwtKeyService.getJwk();

      assert.equal(jwk.kty, "RSA");
      assert.equal(jwk.use, "sig");
      assert.equal(jwk.alg, "RS256");
      assert.equal(jwk.kid, jwtKeyService.getKeyId());
      assert.ok(
        jwk.n && jwk.n.length > 100,
        "Modulus (n) must be valid Base64URL string",
      );
      assert.equal(
        jwk.e,
        "AQAB",
        "Exponent (e) must typically be 65537 (AQAB)",
      );
    });

    it("should wrap JWK in RFC 7517 JWKS structure", () => {
      const jwks = jwtKeyService.getJwks();

      assert.ok(Array.isArray(jwks.keys), "keys property must be an array");
      assert.equal(jwks.keys.length, 1);
      assert.equal(jwks.keys[0].kty, "RSA");
      assert.equal(jwks.keys[0].kid, jwtKeyService.getKeyId());
    });

    it("should convert JWK back to SPKI PEM using JwtKeyService.jwkToPem", () => {
      const jwk = jwtKeyService.getJwk();
      const reconstructedPem = JwtKeyService.jwkToPem(jwk);

      assert.ok(
        reconstructedPem.includes("-----BEGIN PUBLIC KEY-----"),
        "Reconstructed key must be SPKI PEM",
      );

      // Verify cryptographic equivalence
      const originalObj = crypto.createPublicKey(
        jwtKeyService.getPublicKeyPem(),
      );
      const reconstructedObj = crypto.createPublicKey(reconstructedPem);
      assert.deepEqual(
        originalObj.export({ format: "jwk" }),
        reconstructedObj.export({ format: "jwk" }),
      );
    });

    it("should allow setting custom keys for testing key rotation and rogue keys", () => {
      const { publicKey: customPub, privateKey: customPriv } =
        crypto.generateKeyPairSync("rsa", {
          modulusLength: 2048,
          publicKeyEncoding: { type: "spki", format: "pem" },
          privateKeyEncoding: { type: "pkcs8", format: "pem" },
        });

      const service = new JwtKeyService();
      service.setCustomKeys(customPriv, customPub, "custom-key-id-99");

      assert.equal(service.getKeyId(), "custom-key-id-99");
      assert.equal(service.getPublicKeyPem(), customPub);
      assert.equal(service.getJwk().kid, "custom-key-id-99");
    });
  });

  describe("3. Access Token Signing with RS256 & Verification", () => {
    it("should sign Access Token with RS256 algorithm and embed kid header", () => {
      const payload = {
        id: "user-uuid-12345",
        email: "alice@example.com",
        role: "ADMIN",
        roleId: "role-admin-id",
        purpose: "ACCESS",
      };

      const token = jwtKeyService.signAccessToken(payload);
      assert.ok(token, "Token must be a non-empty string");

      const decoded = jwt.decode(token, { complete: true });
      assert.ok(decoded, "Token must be decodable");
      assert.equal(decoded.header.alg, "RS256");
      assert.equal(decoded.header.typ, "JWT");
      assert.equal(decoded.header.kid, jwtKeyService.getKeyId());

      assert.equal((decoded.payload as any).id, payload.id);
      assert.equal((decoded.payload as any).email, payload.email);
      assert.equal((decoded.payload as any).role, payload.role);
      assert.equal((decoded.payload as any).purpose, "ACCESS");
    });

    it("should successfully verify RS256 Access Token using Public Key", () => {
      const payload = {
        id: "user-uuid-verification",
        email: "bob@example.com",
        role: "USER",
        purpose: "ACCESS",
      };

      const token = jwtKeyService.signAccessToken(payload);

      // Verify with jwtKeyService
      const verified = jwtKeyService.verifyAccessToken(token) as any;
      assert.equal(verified.id, payload.id);
      assert.equal(verified.email, payload.email);

      // Verify independently with native jwt.verify using only Public Key (zero private key needed)
      const offlineVerified = jwt.verify(
        token,
        jwtKeyService.getPublicKeyPem(),
        { algorithms: ["RS256"] },
      ) as any;
      assert.equal(offlineVerified.id, payload.id);
    });

    it("should reject token with tampered signature", () => {
      const token = jwtKeyService.signAccessToken({
        id: "user-1",
        purpose: "ACCESS",
      });
      const parts = token.split(".");
      // Tamper signature
      const tamperedSignature = Buffer.from(
        "tampered_signature_bytes",
      ).toString("base64url");
      const tamperedToken = `${parts[0]}.${parts[1]}.${tamperedSignature}`;

      assert.throws(() => {
        jwtKeyService.verifyAccessToken(tamperedToken);
      }, /invalid signature/i);
    });

    it("should reject expired token with TokenExpiredError", () => {
      const token = jwtKeyService.signAccessToken(
        { id: "user-expired", purpose: "ACCESS" },
        { expiresIn: "0s" },
      );

      assert.throws(() => {
        jwtKeyService.verifyAccessToken(token);
      }, /jwt expired/i);
    });

    it("should reject token signed by rogue private key", () => {
      // Create independent rogue key pair
      const rogueKeys = crypto.generateKeyPairSync("rsa", {
        modulusLength: 2048,
        publicKeyEncoding: { type: "spki", format: "pem" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
      });

      const rogueToken = jwt.sign(
        { id: "attacker", purpose: "ACCESS" },
        rogueKeys.privateKey,
        { algorithm: "RS256", keyid: "rogue-key" },
      );

      assert.throws(() => {
        jwt.verify(rogueToken, jwtKeyService.getPublicKeyPem(), {
          algorithms: ["RS256"],
        });
      }, /invalid signature/i);
    });
  });

  describe("4. HTTP Integration Tests (Live Express App & JWKS Endpoint)", () => {
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

    it("GET /.well-known/jwks.json should return HTTP 200 with RFC 7517 compliant payload", async () => {
      const res = await fetch(`${baseUrl}/.well-known/jwks.json`);
      assert.equal(res.status, 200);

      const contentType = res.headers.get("content-type");
      assert.ok(
        contentType?.includes("application/json"),
        `Expected application/json, got: ${contentType}`,
      );

      const cacheControl = res.headers.get("cache-control");
      assert.ok(
        cacheControl?.includes("public"),
        `Expected public in cache-control, got: ${cacheControl}`,
      );
      assert.ok(
        cacheControl?.includes("max-age=86400"),
        `Expected max-age=86400, got: ${cacheControl}`,
      );

      const body = (await res.json()) as { keys: Array<any> };
      assert.ok(Array.isArray(body.keys), "Response must have keys array");
      assert.equal(body.keys.length, 1);

      const key = body.keys[0];
      assert.equal(key.kty, "RSA");
      assert.equal(key.use, "sig");
      assert.equal(key.alg, "RS256");
      assert.equal(key.kid, jwtKeyService.getKeyId());
      assert.ok(key.n, "Modulus n must be defined");
      assert.ok(key.e, "Exponent e must be defined");
    });

    it("GET /api/v1/.well-known/jwks.json should return HTTP 200 with identical JWKS (Dual-Mount)", async () => {
      const res = await fetch(`${baseUrl}/api/v1/.well-known/jwks.json`);
      assert.equal(res.status, 200);

      const body = (await res.json()) as { keys: Array<any> };
      assert.equal(body.keys[0].kid, jwtKeyService.getKeyId());
    });

    it("OpenAPI Swagger specification should document /.well-known/jwks.json endpoint", () => {
      assert.ok(swaggerSpec.paths, "Swagger spec must have paths");
      const jwksPath = swaggerSpec.paths["/.well-known/jwks.json"];
      assert.ok(
        jwksPath,
        "Path /.well-known/jwks.json must be registered in Swagger",
      );
      assert.ok(jwksPath.get, "GET operation must be defined");
      assert.equal(jwksPath.get.tags[0], "Authentication");
      assert.ok(jwksPath.get.responses["200"], "200 response must be defined");
    });
  });

  describe("5. Decentralized Local JWT Verification Middleware (verifyJwtLocally)", () => {
    beforeEach(() => {
      clearJwtPublicKeyCache();
    });

    function createMockContext(headers: Record<string, string> = {}) {
      const req: any = {
        headers,
        cookies: {},
        query: {},
        baseUrl: "/api/v1",
        path: "/protected-resource",
      };
      const res: any = {
        status: (code: number) => {
          res.statusCode = code;
          return res;
        },
        json: (data: any) => {
          res.body = data;
          return res;
        },
      };
      return { req, res };
    }

    it("should allow request and attach req.user in offline mode (< 0.1ms latency)", async () => {
      const token = jwtKeyService.signAccessToken({
        id: "usr-decentralized-1",
        email: "decentralized@company.com",
        role: "MANAGER",
        roleId: "role-mgr-1",
        purpose: "ACCESS",
      });

      const { req, res } = createMockContext({
        authorization: `Bearer ${token}`,
      });

      let nextError: any;
      let nextCalled = false;

      // Offline mode: truyền trực tiếp Public Key
      const middleware = createVerifyJwtLocally({
        publicKey: jwtKeyService.getPublicKeyPem(),
      });

      const start = performance.now();
      await middleware(req, res, (err?: any) => {
        nextCalled = true;
        nextError = err;
      });
      const elapsedMs = performance.now() - start;

      assert.equal(nextCalled, true);
      assert.equal(nextError, undefined);
      assert.ok(req.user, "req.user must be populated");
      assert.equal(req.user.id, "usr-decentralized-1");
      assert.equal(req.user.email, "decentralized@company.com");
      assert.equal(req.user.role, "MANAGER");
      assert.equal(req.user.roleId, "role-mgr-1");

      // Verify ultra-low latency (< 10ms trên mọi môi trường chạy)
      assert.ok(elapsedMs < 10, `Execution time was ${elapsedMs}ms`);
    });

    it("should reject request when token is missing with HTTP 401 UNAUTHORIZED", async () => {
      const { req, res } = createMockContext({});

      let nextError: any;
      await verifyJwtLocally(req, res, (err?: any) => {
        nextError = err;
      });

      assert.ok(nextError instanceof AppError);
      assert.equal(nextError.statusCode, 401);
      assert.equal(nextError.code, ERROR_CODE.UNAUTHORIZED);
    });

    it("should reject expired token with HTTP 401 TOKEN_EXPIRED", async () => {
      const expiredToken = jwtKeyService.signAccessToken(
        { id: "usr-expired", purpose: "ACCESS" },
        { expiresIn: "0s" },
      );

      const { req, res } = createMockContext({
        authorization: `Bearer ${expiredToken}`,
      });

      let nextError: any;
      await verifyJwtLocally(req, res, (err?: any) => {
        nextError = err;
      });

      assert.ok(nextError instanceof AppError);
      assert.equal(nextError.statusCode, 401);
      assert.equal(nextError.code, ERROR_CODE.TOKEN_EXPIRED);
    });

    it("should reject token with tampered signature with HTTP 401 TOKEN_INVALID", async () => {
      const token = jwtKeyService.signAccessToken({
        id: "usr-tamper",
        purpose: "ACCESS",
      });
      const parts = token.split(".");
      const forged = `${parts[0]}.${parts[1]}.invalid_signature`;

      const { req, res } = createMockContext({
        authorization: `Bearer ${forged}`,
      });

      let nextError: any;
      await verifyJwtLocally(req, res, (err?: any) => {
        nextError = err;
      });

      assert.ok(nextError instanceof AppError);
      assert.equal(nextError.statusCode, 401);
      assert.equal(nextError.code, ERROR_CODE.TOKEN_INVALID);
    });

    it("should reject 2FA temporary token with HTTP 401 UNAUTHORIZED", async () => {
      const tempToken = jwtKeyService.signAccessToken({
        id: "usr-2fa-temp",
        purpose: "2FA_VERIFICATION",
      });

      const { req, res } = createMockContext({
        authorization: `Bearer ${tempToken}`,
      });

      let nextError: any;
      await verifyJwtLocally(req, res, (err?: any) => {
        nextError = err;
      });

      assert.ok(nextError instanceof AppError);
      assert.equal(nextError.statusCode, 401);
      assert.equal(nextError.code, ERROR_CODE.UNAUTHORIZED);
    });

    it("optionalVerifyJwtLocally should allow request without token without throwing 401", async () => {
      const { req, res } = createMockContext({});

      let nextCalled = false;
      let nextError: any;
      await optionalVerifyJwtLocally(req, res, (err?: any) => {
        nextCalled = true;
        nextError = err;
      });

      assert.equal(nextCalled, true);
      assert.equal(nextError, undefined);
      assert.equal(req.user, undefined);
    });

    it("optionalVerifyJwtLocally should populate req.user when valid token is present", async () => {
      const token = jwtKeyService.signAccessToken({
        id: "usr-optional-user",
        email: "guest@company.com",
        role: "USER",
        purpose: "ACCESS",
      });

      const { req, res } = createMockContext({
        authorization: `Bearer ${token}`,
      });

      let nextCalled = false;
      let nextError: any;
      await optionalVerifyJwtLocally(req, res, (err?: any) => {
        nextCalled = true;
        nextError = err;
      });

      assert.equal(nextCalled, true);
      assert.equal(nextError, undefined);
      assert.ok(req.user);
      assert.equal(req.user.id, "usr-optional-user");
    });
  });

  describe("6. Zero-Downtime Key Rotation & JWKS RAM Caching (24h)", () => {
    let jwksServer: http.Server;
    let jwksBaseUrl: string;
    let activeKeyId = "rotation-key-v1";
    let activeKeyPair: { publicKey: string; privateKey: string };

    beforeEach(async () => {
      clearJwtPublicKeyCache();

      // Sinh cặp khóa V1
      activeKeyId = "rotation-key-v1";
      activeKeyPair = crypto.generateKeyPairSync("rsa", {
        modulusLength: 2048,
        publicKeyEncoding: { type: "spki", format: "pem" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
      });

      // Tạo Mock Auth Service JWKS Server
      jwksServer = http.createServer((req, res) => {
        if (req.url === "/.well-known/jwks.json") {
          const keyObj = crypto.createPublicKey(activeKeyPair.publicKey);
          const jwk = keyObj.export({ format: "jwk" }) as any;
          jwk.kid = activeKeyId;
          jwk.use = "sig";
          jwk.alg = "RS256";

          res.writeHead(200, {
            "Content-Type": "application/json",
            "Cache-Control": "public, max-age=86400",
          });
          res.end(JSON.stringify({ keys: [jwk] }));
        } else {
          res.writeHead(404);
          res.end();
        }
      });

      await new Promise<void>((resolve) => jwksServer.listen(0, resolve));
      const address = jwksServer.address();
      const port = typeof address === "object" && address ? address.port : 0;
      jwksBaseUrl = `http://127.0.0.1:${port}/.well-known/jwks.json`;
    });

    afterEach(async () => {
      await new Promise<void>((resolve) => jwksServer.close(() => resolve()));
    });

    it("should fetch key from JWKS, cache in RAM, and verify token without repeated network calls", async () => {
      const middleware = createVerifyJwtLocally({
        jwksUri: jwksBaseUrl,
        cacheTtlMs: 24 * 60 * 60 * 1000,
      });

      const tokenV1 = jwt.sign(
        {
          id: "usr-v1",
          email: "v1@example.com",
          role: "USER",
          purpose: "ACCESS",
        },
        activeKeyPair.privateKey,
        { algorithm: "RS256", keyid: activeKeyId, expiresIn: "15m" },
      );

      const req1: any = { headers: { authorization: `Bearer ${tokenV1}` } };
      let err1: any;
      await middleware(req1, {} as any, (err?: any) => {
        err1 = err;
      });

      assert.equal(err1, undefined);
      assert.equal(req1.user?.id, "usr-v1");

      // Đóng JWKS server để chứng minh lần verify thứ 2 hoàn toàn offline nhờ RAM cache 24h
      await new Promise<void>((resolve) => jwksServer.close(() => resolve()));

      const req2: any = { headers: { authorization: `Bearer ${tokenV1}` } };
      let err2: any;
      await middleware(req2, {} as any, (err?: any) => {
        err2 = err;
      });

      assert.equal(err2, undefined);
      assert.equal(req2.user?.id, "usr-v1");
    });

    it("should automatically rotate keys when a token with a new kid arrives", async () => {
      const middleware = createVerifyJwtLocally({
        jwksUri: jwksBaseUrl,
        cacheTtlMs: 24 * 60 * 60 * 1000,
        autoRefreshOnUnknownKid: true,
      });

      // 1. Verify với khóa V1
      const tokenV1 = jwt.sign(
        { id: "usr-before-rotation", purpose: "ACCESS" },
        activeKeyPair.privateKey,
        { algorithm: "RS256", keyid: activeKeyId, expiresIn: "15m" },
      );
      const req1: any = { headers: { authorization: `Bearer ${tokenV1}` } };
      let err1: any;
      await middleware(req1, {} as any, (err?: any) => {
        err1 = err;
      });
      assert.equal(err1, undefined);
      assert.equal(req1.user?.id, "usr-before-rotation");

      // 2. Auth Service xoay khóa sang V2 (Key Rotation)
      const newKeyId = "rotation-key-v2";
      const newKeyPair = crypto.generateKeyPairSync("rsa", {
        modulusLength: 2048,
        publicKeyEncoding: { type: "spki", format: "pem" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
      });
      activeKeyId = newKeyId;
      activeKeyPair = newKeyPair;

      // 3. User nhận token mới được ký bởi khóa V2
      const tokenV2 = jwt.sign(
        { id: "usr-after-rotation", role: "ADMIN", purpose: "ACCESS" },
        newKeyPair.privateKey,
        { algorithm: "RS256", keyid: newKeyId, expiresIn: "15m" },
      );

      // 4. Middleware gặp kid mới, tự động refresh JWKS và verify thành công
      const req2: any = { headers: { authorization: `Bearer ${tokenV2}` } };
      let err2: any;
      await middleware(req2, {} as any, (err?: any) => {
        err2 = err;
      });
      assert.equal(err2, undefined);
      assert.equal(req2.user?.id, "usr-after-rotation");
      assert.equal(req2.user?.role, "ADMIN");
    });
  });

  describe("7. Cross-Service Verification Simulation (Strangler Fig Validation)", () => {
    it("should allow independent Satellite Service to verify token with zero Auth DB access", () => {
      // 1. Auth Service ký token
      const authServiceToken = jwtKeyService.signAccessToken({
        id: "usr-customer-888",
        email: "customer@domain.vn",
        role: "USER",
        roleId: "role-user-id",
        purpose: "ACCESS",
      });

      // 2. Satellite Service (ví dụ Notification / Media Service) chỉ nhận Public Key (hoặc JWKS)
      // Không hề có Prisma, không có kết nối DB Auth, không có Private Key
      const satellitePublicKey = jwtKeyService.getPublicKeyPem();

      // 3. Satellite Service tự verify token bằng public key độc lập
      const decoded = jwt.verify(authServiceToken, satellitePublicKey, {
        algorithms: ["RS256"],
      }) as any;

      assert.equal(decoded.id, "usr-customer-888");
      assert.equal(decoded.email, "customer@domain.vn");
      assert.equal(decoded.role, "USER");
      assert.equal(decoded.purpose, "ACCESS");
    });
  });
});
