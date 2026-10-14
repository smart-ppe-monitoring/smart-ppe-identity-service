import { SwaggerUiOptions } from "swagger-ui-express";
import { buildOpenApiSpec } from "./openapi/openapi.registry";
import { registerAuthOpenApi } from "../modules/auth/auth.openapi";
import { registerUserOpenApi } from "../modules/users/user.openapi";
import { registerRbacOpenApi } from "../modules/rbac/rbac.openapi";
import { registerMaintenanceOpenApi } from "../modules/maintenance/maintenance.openapi";
import { registerIntegrationOpenApi } from "../modules/integration/integration.openapi";
import { registerSystemConfigOpenApi } from "../modules/system-config/system-config.openapi";
import { registerCronOpenApi } from "../modules/cron/cron.openapi";
import { registerHealthOpenApi } from "../modules/health/health.openapi";
import { registerSecurityTxtOpenApi } from "../modules/security-txt/security-txt.openapi";
import { registerJwksOpenApi } from "../modules/jwks/jwks.openapi";

// Tự động khởi tạo và đăng ký 100% routes & schemas từ Zod validation schemas
registerAuthOpenApi();
registerUserOpenApi();
registerRbacOpenApi();
registerMaintenanceOpenApi();
registerIntegrationOpenApi();
registerSystemConfigOpenApi();
registerCronOpenApi();
registerHealthOpenApi();
registerSecurityTxtOpenApi();
registerJwksOpenApi();

export const swaggerOptions: SwaggerUiOptions | Record<string, any> = {
  explorer: true,
  swaggerUrls: [
    { url: "/api/docs/specs/identity.json", name: "1. Identity & Auth Service (:9999)" },
    { url: "/api/docs/specs/site.json", name: "2. Site & Safety Rules Service (:8891)" },
    { url: "/api/docs/specs/camera.json", name: "3. Camera & Streams Service (:8892)" },
    { url: "/api/docs/specs/incident.json", name: "4. Incident & Violations Service (:8893)" },
    { url: "/api/docs/specs/media.json", name: "5. Media & Storage Service (:8890)" },
    { url: "/api/docs/specs/reporting.json", name: "6. Reporting & Analytics Service (:8894)" },
    { url: "/api/docs/specs/notification.json", name: "7. Notification & Alerts Service (:8889)" },
  ],
  customCss: `
    .swagger-ui .topbar { background-color: #1a1a2e; }
    .swagger-ui .topbar-wrapper .link img { display: none; }
    .swagger-ui .topbar-wrapper .link::after { content: 'Smart PPE Monitoring'; color: white; font-size: 1.2rem; font-weight: bold; margin-right: 15px; }
  `,
  customSiteTitle: "Smart PPE Monitoring - API Documentation",
};

export const swaggerSpec: Record<string, any> = buildOpenApiSpec();
