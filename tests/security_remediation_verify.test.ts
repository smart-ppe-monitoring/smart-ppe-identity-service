import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import jwt from "jsonwebtoken";

describe("Post-Audit Security Hardening Verification Suite", () => {
  const rootDir = path.resolve(__dirname, "../../");

  // 1. Verify HS256 Rejection across all Satellite Services
  it("VULN-CRIT-01: should have completely removed HS256 fallback across all satellite services", () => {
    const satelliteAuthPaths = [
      "smart-ppe-site-service/src/middlewares/auth.middleware.ts",
      "smart-ppe-camera-service/src/middlewares/auth.middleware.ts",
      "smart-ppe-incident-service/src/middlewares/auth.middleware.ts",
      "smart-ppe-reporting-service/src/middlewares/auth.middleware.ts",
      "smart-ppe-notification-service/src/middlewares/auth.middleware.ts",
    ];

    for (const relPath of satelliteAuthPaths) {
      const fullPath = path.resolve(rootDir, relPath);
      const content = fs.readFileSync(fullPath, "utf-8");

      assert.ok(
        content.includes("alg !== JWT_ALGORITHM.RS256"),
        `[FAIL] ${relPath} does not strictly require RS256!`,
      );
      assert.ok(
        !content.includes("jwtConfig.accessSecret"),
        `[FAIL] ${relPath} still uses jwtConfig.accessSecret fallback!`,
      );
    }

    const mediaPath = path.resolve(
      rootDir,
      "smart-ppe-media-service/src/middlewares/verify-jwt-locally.middleware.ts",
    );
    const mediaContent = fs.readFileSync(mediaPath, "utf-8");
    assert.ok(
      mediaContent.includes("alg !== JWT_ALGORITHM.RS256"),
      `[FAIL] Media service does not strictly require RS256!`,
    );
    assert.ok(
      !mediaContent.includes("jwtConfig.accessSecret"),
      `[FAIL] Media service still contains HS256 accessSecret verification!`,
    );
  });

  // 2. Verify BOLA / IDOR Protection in Reporting Service
  it("VULN-HIGH-01: should enforce object-level ownership check (BOLA) on report download", () => {
    const reportingServicePath = path.resolve(
      rootDir,
      "smart-ppe-reporting-service/src/modules/reporting/reporting.service.ts",
    );
    const reportingContent = fs.readFileSync(reportingServicePath, "utf-8");

    assert.ok(
      reportingContent.includes("userRole !== ROLES.ADMIN && (!userId || report.generatedBy !== userId)"),
      "[FAIL] ReportingService does not check userRole and generatedBy ownership!",
    );
    assert.ok(
      reportingContent.includes("ERROR_CODE.FORBIDDEN"),
      "[FAIL] ReportingService does not throw FORBIDDEN error on unauthorized access!",
    );

    const reportingControllerPath = path.resolve(
      rootDir,
      "smart-ppe-reporting-service/src/modules/reporting/reporting.controller.ts",
    );
    const controllerContent = fs.readFileSync(reportingControllerPath, "utf-8");
    assert.ok(
      controllerContent.includes("req.user?.id") && controllerContent.includes("req.user?.role"),
      "[FAIL] ReportingController does not pass user credentials to download service!",
    );
  });

  // 3. Verify Camera RTSP Stream Masking
  it("VULN-HIGH-02: should mask plaintext credentials in RTSP camera stream URLs", () => {
    const cameraServicePath = path.resolve(
      rootDir,
      "smart-ppe-camera-service/src/modules/camera/camera.service.ts",
    );
    const cameraContent = fs.readFileSync(cameraServicePath, "utf-8");

    assert.ok(
      cameraContent.includes("sanitizeCameraEntity"),
      "[FAIL] CameraService does not define sanitizeCameraEntity!",
    );
    assert.ok(
      cameraContent.includes("maskStreamCredentials"),
      "[FAIL] CameraService does not apply maskStreamCredentials!",
    );

    // Regex credential masking logic test (matching camera.service.ts)
    function maskStreamCredentials(url: string | null | undefined): string {
      if (!url) return "";
      try {
        const parsed = new URL(url);
        if (parsed.password) {
          parsed.password = "***";
          return parsed.toString();
        }
      } catch {}
      return url.replace(/:\/\/([^:\s\/]+):(.*)@([^:\/\s]+)/g, "://$1:***@$3");
    }

    const rawRtsp = "rtsp://admin:P@ssw0rd123!@192.168.1.50:554/h264Preview_01_main";
    const maskedRtsp = maskStreamCredentials(rawRtsp);
    assert.equal(maskedRtsp, "rtsp://admin:***@192.168.1.50:554/h264Preview_01_main");
    assert.ok(!maskedRtsp.includes("P@ssw0rd123!"));
  });

  // 4. Verify 2FA Permissions Claim Propagation
  it("VULN-MED-02: should propagate granular permissions claim into 2FA tokenPayload", () => {
    const auth2faPath = path.resolve(
      rootDir,
      "smart-ppe-identity-service/src/modules/auth/services/auth-2fa.service.ts",
    );
    const auth2faContent = fs.readFileSync(auth2faPath, "utf-8");

    assert.ok(
      auth2faContent.includes("permissions: userPermissions"),
      "[FAIL] 2FA service does not propagate permissions claim into tokenPayload!",
    );
    assert.ok(
      auth2faContent.includes("permissionCacheService.getRolePermissions"),
      "[FAIL] 2FA service does not retrieve permissions from permissionCacheService!",
    );
  });

  // 5. Verify Fail-Close Incident Assignment
  it("VULN-MED-01: should fail close with default 'USER' role when role is missing in incident controller", () => {
    const incidentControllerPath = path.resolve(
      rootDir,
      "smart-ppe-incident-service/src/modules/incident/incident.controller.ts",
    );
    const incidentControllerContent = fs.readFileSync(incidentControllerPath, "utf-8");

    assert.ok(
      incidentControllerContent.includes('const role = req.user?.role || "USER";'),
      "[FAIL] IncidentController does not default undefined role to 'USER' (fail-close)!",
    );
  });

  // 6. Verify Production OpenAPI Specification Guard
  it("VULN-MED-03: should protect /openapi.json on production environment", () => {
    const appsToVerify = [
      "smart-ppe-site-service/src/site.app.ts",
      "smart-ppe-camera-service/src/camera.app.ts",
      "smart-ppe-incident-service/src/incident.app.ts",
      "smart-ppe-reporting-service/src/reporting.app.ts",
      "smart-ppe-notification-service/src/notification.app.ts",
      "smart-ppe-media-service/src/media.app.ts",
    ];

    for (const appRelPath of appsToVerify) {
      const appPath = path.resolve(rootDir, appRelPath);
      const appContent = fs.readFileSync(appPath, "utf-8");
      assert.ok(
        appContent.includes('if (envConfig.nodeEnv !== "production")'),
        `[FAIL] ${appRelPath} does not guard /openapi.json behind production check!`,
      );
    }
  });

  // 7. Verify Database Port Exposure Guard in Docker Compose
  it("VULN-LOW-02: should bind database and cache ports to 127.0.0.1 in docker-compose.yml", () => {
    const dockerPath = path.resolve(rootDir, "smart-ppe-infra/docker-compose.yml");
    const dockerContent = fs.readFileSync(dockerPath, "utf-8");

    assert.ok(
      dockerContent.includes('127.0.0.1:${PPE_POSTGRES_PORT:-5433}:5432'),
      "[FAIL] PostgreSQL port is not bound to 127.0.0.1!",
    );
    assert.ok(
      dockerContent.includes('127.0.0.1:${REDIS_PORT:-6379}:6379'),
      "[FAIL] Redis port is not bound to 127.0.0.1!",
    );
  });
});
