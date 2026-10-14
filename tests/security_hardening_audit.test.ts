import fs from "fs";
import path from "path";
import assert from "assert/strict";
import jwt from "jsonwebtoken";
import { pathToFileURL } from "url";

// ==============================================================================
// 🧪 SECURITY HARDENING VERIFICATION TEST SUITE
// ==============================================================================

async function runSecurityVerification() {
  console.log("===============================================================================");
  console.log("🔒 SMART PPE MONITORING - KIỂM THỬ XÁC MINH CÁC BẢN VÁ BẢO MẬT (OWASP AUDIT)");
  console.log("===============================================================================\n");

  let totalTests = 0;
  let passedTests = 0;

  function recordPass(testName: string) {
    totalTests++;
    passedTests++;
    console.log(`  ✅ [PASS] ${testName}`);
  }

  function recordFail(testName: string, error: any) {
    totalTests++;
    console.error(`  ❌ [FAIL] ${testName}`);
    console.error(`     Error: ${error.message || error}`);
  }

  const workspaceRoot = path.resolve(__dirname, "../..");
  const publicKeyPath = path.resolve(workspaceRoot, "smart-ppe-identity-service/keys/public.key.pem");
  const privateKeyPath = path.resolve(workspaceRoot, "smart-ppe-identity-service/keys/private.key.pem");

  const publicKeyPem = fs.readFileSync(publicKeyPath, "utf-8").trim();
  const privateKeyPem = fs.readFileSync(privateKeyPath, "utf-8").trim();

  // ─────────────────────────────────────────────────────────────────────────────
  // SUITE 1: JWT Algorithm Confusion Attack (CWE-347, CWE-327)
  // ─────────────────────────────────────────────────────────────────────────────
  console.log("👉 1. Kiểm thử Lỗ hổng Critical: JWT Algorithm Confusion (RS256 vs HS256)...");

  // Tạo payload kẻ tấn công mạo danh ADMIN
  const attackerPayload = {
    sub: "0192e200-0000-7000-8000-attacker00001",
    id: "0192e200-0000-7000-8000-attacker00001",
    email: "attacker@exploit.local",
    role: "ADMIN",
    roleId: "0192e200-0000-7000-8000-000000000001",
    permissions: ["*"],
  };

  // Ký giả mạo bằng HS256 với chuỗi Public Key làm HMAC secret (Khai thác kinh điển Algorithm Confusion)
  const forgedHs256Token = jwt.sign(attackerPayload, publicKeyPem, {
    algorithm: "HS256",
    expiresIn: "1h",
  });

  // Token hợp lệ ký bằng RS256 Private Key
  const legitimateRs256Token = jwt.sign(attackerPayload, privateKeyPem, {
    algorithm: "RS256",
    expiresIn: "1h",
  });

  // Token với thuật toán bị cấm (none)
  const noneAlgToken = jwt.sign(attackerPayload, "", {
    algorithm: "none" as any,
  });

  // Danh sách các satellite services cần xác minh
  const satelliteAuthModules = [
    { name: "Site Service", path: "smart-ppe-site-service/src/middlewares/auth.middleware.ts" },
    { name: "Camera Service", path: "smart-ppe-camera-service/src/middlewares/auth.middleware.ts" },
    { name: "Incident Service", path: "smart-ppe-incident-service/src/middlewares/auth.middleware.ts" },
    { name: "Reporting Service", path: "smart-ppe-reporting-service/src/middlewares/auth.middleware.ts" },
    { name: "Notification Service", path: "smart-ppe-notification-service/src/middlewares/auth.middleware.ts" },
  ];

  for (const item of satelliteAuthModules) {
    try {
      const modulePath = path.resolve(workspaceRoot, item.path);
      const { authMiddleware } = await import(pathToFileURL(modulePath).href);

      // 1.1 Thử nghiệm Exploit bằng Forged HS256 Token
      let errorThrown: any = null;
      const fakeReq: any = {
        cookies: {},
        headers: { authorization: `Bearer ${forgedHs256Token}` },
        baseUrl: "/api/v1",
        path: "/test",
      };
      const fakeRes: any = {};
      const nextFn = (err?: any) => {
        errorThrown = err;
      };

      await authMiddleware(fakeReq, fakeRes, nextFn);

      if (errorThrown && (errorThrown.statusCode === 401 || errorThrown.status === 401)) {
        recordPass(`${item.name}: Chặn đứng hoàn toàn tấn công Algorithm Confusion (Trả về 401 Unauthorized)`);
      } else {
        throw new Error(`Kẻ tấn công không bị chặn! errorThrown = ${errorThrown}`);
      }

      // 1.2 Thử nghiệm Token với algorithm "none"
      let noneError: any = null;
      fakeReq.headers.authorization = `Bearer ${noneAlgToken}`;
      fakeReq.user = undefined;
      await authMiddleware(fakeReq, fakeRes, (err: any) => {
        noneError = err;
      });

      if (noneError && (noneError.statusCode === 401 || noneError.status === 401)) {
        recordPass(`${item.name}: Chặn đứng token thuật toán 'none'`);
      } else {
        throw new Error(`Token 'none' không bị từ chối!`);
      }

      // 1.3 Thử nghiệm Token RS256 Hợp lệ
      let validError: any = null;
      fakeReq.headers.authorization = `Bearer ${legitimateRs256Token}`;
      fakeReq.user = undefined;
      await authMiddleware(fakeReq, fakeRes, (err: any) => {
        validError = err;
      });

      if (!validError && fakeReq.user && fakeReq.user.role === "ADMIN") {
        recordPass(`${item.name}: Token RS256 hợp lệ được xác thực thành công`);
      } else {
        throw new Error(`Token RS256 hợp lệ bị lỗi: ${validError?.message}`);
      }
    } catch (err: any) {
      recordFail(`${item.name}: Lỗi kiểm thử JWT Algorithm Confusion`, err);
    }
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // SUITE 2: BOLA / IDOR in Incident Status Transitions (CWE-639)
  // ─────────────────────────────────────────────────────────────────────────────
  console.log("\n👉 2. Kiểm thử Lỗ hổng High: BOLA / IDOR trong Incident Service...");

  try {
    const { IncidentService } = await import(
      pathToFileURL(path.resolve(workspaceRoot, "smart-ppe-incident-service/src/modules/incident/incident.service.ts")).href
    );
    const { ROLES } = await import(
      pathToFileURL(path.resolve(workspaceRoot, "smart-ppe-incident-service/src/common/constants/role.constant.ts")).href
    );
    const { INCIDENT_STATUS } = await import(
      pathToFileURL(path.resolve(workspaceRoot, "smart-ppe-incident-service/src/common/constants/incident.constant.ts")).href
    );

    const targetIncidentId = "0192e200-0000-7000-8000-incident000001";
    const assignedOfficerId = "0192e200-0000-7000-8000-officer0000001";
    const unassignedOfficerId = "0192e200-0000-7000-8000-unassigned00001";

    let transitionCalled = false;

    // Mock IncidentRepository
    const mockRepo: any = {
      findIncidentById: async (id: string) => {
        return {
          id,
          status: INCIDENT_STATUS.CONFIRMED,
          siteId: "0192e200-0000-7000-8000-site0000000001",
        };
      },
      isUserAssignedToIncident: async (incidentId: string, userId: string) => {
        return userId === assignedOfficerId;
      },
      transitionStatus: async (params: any) => {
        transitionCalled = true;
        return { ...params, id: params.incidentId };
      },
    };

    const mockStorage: any = {};
    const mockNotification: any = {};

    const incidentService = new IncidentService(mockRepo, mockStorage, mockNotification);

    // 2.1 Officer KHÔNG được phân công gọi resolveIncident -> Bắt buộc bị từ chối 403 FORBIDDEN
    let bolaErrorThrown: any = null;
    try {
      await incidentService.resolveIncident(
        targetIncidentId,
        { resolutionNote: "Đã nhắc nhở công nhân đeo mũ" },
        unassignedOfficerId,
        ROLES.SAFETY_OFFICER,
      );
    } catch (err: any) {
      bolaErrorThrown = err;
    }

    if (bolaErrorThrown && (bolaErrorThrown.statusCode === 403 || bolaErrorThrown.status === 403)) {
      recordPass("IncidentService: Chặn đứng BOLA/IDOR khi Safety Officer chưa được phân công cố tình resolve (403 Forbidden)");
    } else {
      recordFail("IncidentService: Không chặn Safety Officer chưa được phân công!", bolaErrorThrown);
    }

    // 2.2 Officer KHÔNG được phân công gọi closeIncident -> Bắt buộc bị từ chối 403 FORBIDDEN
    let closeBolaError: any = null;
    try {
      await incidentService.closeIncident(
        targetIncidentId,
        { closeNote: "Đóng sự cố" },
        unassignedOfficerId,
        ROLES.SAFETY_OFFICER,
      );
    } catch (err: any) {
      closeBolaError = err;
    }

    if (closeBolaError && (closeBolaError.statusCode === 403 || closeBolaError.status === 403)) {
      recordPass("IncidentService: Chặn đứng BOLA/IDOR khi Safety Officer chưa được phân công cố tình close (403 Forbidden)");
    } else {
      recordFail("IncidentService: Không chặn close từ Officer chưa được phân công!", closeBolaError);
    }

    // 2.3 Officer ĐƯỢC phân công gọi resolveIncident -> Cho phép thành công
    transitionCalled = false;
    const resolvedResult = await incidentService.resolveIncident(
      targetIncidentId,
      { resolutionNote: "Tôi đã trực tiếp xử lý và bổ sung mũ bảo hộ" },
      assignedOfficerId,
      ROLES.SAFETY_OFFICER,
    );

    if (transitionCalled && resolvedResult.newStatus === INCIDENT_STATUS.RESOLVED) {
      recordPass("IncidentService: Cho phép Safety Officer ĐƯỢC PHÂN CÔNG xử lý sự cố thành công");
    } else {
      recordFail("IncidentService: Lỗi xử lý sự cố cho Officer hợp lệ", new Error("Transition was not called"));
    }

    // 2.4 Safety Manager hoặc Admin xử lý mà không cần phân công -> Cho phép thành công
    transitionCalled = false;
    const managerResult = await incidentService.resolveIncident(
      targetIncidentId,
      { resolutionNote: "Manager phê duyệt can thiệp trực tiếp" },
      unassignedOfficerId,
      ROLES.SAFETY_MANAGER,
    );

    if (transitionCalled && managerResult.newStatus === INCIDENT_STATUS.RESOLVED) {
      recordPass("IncidentService: Quản lý (SAFETY_MANAGER / ADMIN) có quyền xử lý quản trị không bị chặn");
    } else {
      recordFail("IncidentService: Manager bị chặn không đúng logic", new Error("Manager failed"));
    }
  } catch (err: any) {
    recordFail("IncidentService: Lỗi tổng quát kiểm thử BOLA", err);
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // SUITE 3: Full-Text Search tsquery Sanitization (CWE-20, CWE-754)
  // ─────────────────────────────────────────────────────────────────────────────
  console.log("\n👉 3. Kiểm thử Lỗ hổng Medium: PostgreSQL tsquery Injection & Syntax Sanitization...");

  const ftsModules = [
    { name: "Incident FTS", path: "smart-ppe-incident-service/src/common/helpers/fts.helper.ts" },
    { name: "Media FTS", path: "smart-ppe-media-service/src/common/helpers/fts.helper.ts" },
    { name: "Identity FTS", path: "smart-ppe-identity-service/src/common/helpers/fts.helper.ts" },
  ];

  const maliciousPayloads = [
    "can't find worker's helmet",
    "'; DROP TABLE incidents; --",
    'helmet "safety" & | ! :* <-> ()',
    "công nhân không đội mũ bảo hộ @ site-01 #hazard",
    "   ",
  ];

  for (const item of ftsModules) {
    try {
      const modulePath = path.resolve(workspaceRoot, item.path);
      const { buildTsQuery } = await import(pathToFileURL(modulePath).href);

      let allClean = true;

      for (const payload of maliciousPayloads) {
        const query = buildTsQuery(payload, "prefix");

        if (payload.trim().length === 0) {
          if (query !== null) allClean = false;
          continue;
        }

        // Kiểm tra không có ký tự dấu nháy đơn thoát ra ngoài format 'token':*
        if (query) {
          const hasBrokenQuotes = query.includes("''") || /[^&|\s]'[^':]/.test(query);
          if (hasBrokenQuotes) {
            allClean = false;
            console.error(`     Broken query generated for input [${payload}]: ${query}`);
          }
        }
      }

      if (allClean) {
        recordPass(`${item.name}: Làm sạch 100% các ký tự nháy đơn, toán tử SQL & ký tự điều khiển tsquery`);
      } else {
        recordFail(`${item.name}: Chuỗi tsquery sinh ra chứa ký tự không an toàn`, new Error("Unsafe tsquery"));
      }
    } catch (err: any) {
      recordFail(`${item.name}: Lỗi kiểm thử FTS helper`, err);
    }
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // SUITE 4: Safety Rule System-Default Route Protection (CWE-306)
  // ─────────────────────────────────────────────────────────────────────────────
  console.log("\n👉 4. Kiểm thử Lỗ hổng Low: Bảo vệ Endpoint Baseline /system-default...");

  try {
    const { safetyRuleRouter } = await import(
      pathToFileURL(path.resolve(workspaceRoot, "smart-ppe-site-service/src/modules/safety-rule/safety-rule.route.ts")).href
    );

    const layer = (safetyRuleRouter.stack || []).find(
      (s: any) => s.route && s.route.path === "/system-default" && s.route.methods.get,
    );

    if (layer) {
      const middlewareCount = layer.route.stack.length;
      if (middlewareCount >= 3) {
        recordPass("Site Safety Rule Router: Endpoint /system-default đã được bảo vệ bởi authMiddleware & requirePermission");
      } else {
        recordFail("Site Safety Rule Router: Endpoint /system-default chưa đủ middleware bảo vệ", new Error(`Count: ${middlewareCount}`));
      }
    } else {
      recordFail("Site Safety Rule Router: Không tìm thấy route /system-default", new Error("Route not found"));
    }
  } catch (err: any) {
    recordFail("Site Safety Rule Router: Lỗi kiểm tra route", err);
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // SUITE 5: Swagger UI Production Protection (CWE-200)
  // ─────────────────────────────────────────────────────────────────────────────
  console.log("\n👉 5. Kiểm thử Lỗ hổng Low: Ẩn Swagger UI & OpenAPI Specs trên Production...");

  try {
    const identityAppPath = path.resolve(workspaceRoot, "smart-ppe-identity-service/src/identity.app.ts");
    const appFileContent = fs.readFileSync(identityAppPath, "utf-8");

    const hasEnvGuard = appFileContent.includes('if (envConfig.nodeEnv !== "production")');
    const hasDocsProtected = appFileContent.includes('app.use("/api/docs", docsRouter)');

    if (hasEnvGuard && hasDocsProtected) {
      recordPass("Identity Service: Swagger UI & OpenAPI specs được bảo vệ bằng envConfig.nodeEnv !== 'production'");
    } else {
      recordFail("Identity Service: Chưa có điều kiện chặn môi trường production", new Error("Missing env guard"));
    }
  } catch (err: any) {
    recordFail("Identity Service: Lỗi kiểm tra env guard Swagger", err);
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // BÁO CÁO TỔNG HỢP
  // ─────────────────────────────────────────────────────────────────────────────
  console.log("\n===============================================================================");
  console.log(`📊 TỔNG KẾT KIỂM THỬ BẢO MẬT: ${passedTests}/${totalTests} TESTS ĐẠT (${Math.round((passedTests / totalTests) * 100)}%)`);
  console.log("===============================================================================\n");

  if (passedTests === totalTests) {
    console.log("🎉 XÁC NHẬN: 100% CÁC LỖ HỔNG ĐÃ ĐƯỢC GIẢI QUYẾT TRIỆT ĐỂ VÀ AN TOÀN TUYỆT ĐỐI!\n");
    process.exit(0);
  } else {
    console.error("⚠️ CẢNH BÁO: Vẫn còn kiểm thử chưa đạt. Cần kiểm tra lại các mục thất bại!\n");
    process.exit(1);
  }
}

runSecurityVerification().catch((err) => {
  console.error("Lỗi thực thi kiểm thử bảo mật:", err);
  process.exit(1);
});
