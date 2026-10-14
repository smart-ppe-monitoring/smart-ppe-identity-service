import { Router, Request, Response } from "express";
import http from "node:http";
import { swaggerSpec } from "../../config/swagger.config";

export const docsRouter = Router();

interface ServiceConfig {
  name: string;
  hostDocker: string;
  port: number;
  path: string;
}

const SATELLITE_SERVICES: Record<string, ServiceConfig> = {
  site: { name: "Site Service", hostDocker: "site-service", port: 8891, path: "/openapi.json" },
  camera: { name: "Camera Service", hostDocker: "camera-service", port: 8892, path: "/openapi.json" },
  incident: { name: "Incident Service", hostDocker: "incident-service", port: 8893, path: "/openapi.json" },
  media: { name: "Media Service", hostDocker: "media-service", port: 8890, path: "/openapi.json" },
  reporting: { name: "Reporting Service", hostDocker: "reporting-service", port: 8894, path: "/openapi.json" },
  notification: { name: "Notification Service", hostDocker: "notification-service", port: 8889, path: "/openapi.json" },
};

const specCache = new Map<string, any>();

async function fetchFromHttp(host: string, port: number, path: string): Promise<any> {
  return new Promise((resolve, reject) => {
    const req = http.get(
      {
        hostname: host,
        port,
        path,
        timeout: 4000,
      },
      (res) => {
        if (res.statusCode !== 200) {
          return reject(new Error(`HTTP ${res.statusCode}`));
        }
        let body = "";
        res.on("data", (chunk) => (body += chunk));
        res.on("end", () => {
          try {
            resolve(JSON.parse(body));
          } catch (e) {
            reject(e);
          }
        });
      }
    );
    req.on("error", reject);
    req.on("timeout", () => {
      req.destroy();
      reject(new Error("Timeout"));
    });
  });
}

export async function getServiceSpec(serviceKey: string): Promise<any> {
  if (serviceKey === "identity") {
    return swaggerSpec;
  }

  const target = SATELLITE_SERVICES[serviceKey];
  if (!target) {
    throw new Error(`Dịch vụ không tồn tại: ${serviceKey}`);
  }

  // 1. Thử gọi trong mạng Docker network
  try {
    const spec = await fetchFromHttp(target.hostDocker, target.port, target.path);
    specCache.set(serviceKey, spec);
    return spec;
  } catch {
    // 2. Thử gọi localhost nếu đang chạy trên host
    try {
      const spec = await fetchFromHttp("127.0.0.1", target.port, target.path);
      specCache.set(serviceKey, spec);
      return spec;
    } catch (err: any) {
      if (specCache.has(serviceKey)) {
        return specCache.get(serviceKey);
      }
      throw new Error(
        `Không thể tải OpenAPI spec từ ${target.name} (${target.hostDocker}:${target.port}): ${err.message}`
      );
    }
  }
}

// Endpoint trả về OpenAPI JSON spec cho từng service
docsRouter.get("/specs/:service", async (req: Request, res: Response) => {
  const serviceKey = req.params.service.replace(/\.json$/, "").toLowerCase();
  try {
    const spec = await getServiceSpec(serviceKey);
    res.setHeader("Content-Type", "application/json");
    return res.status(200).send(JSON.stringify(spec, null, 2));
  } catch (err: any) {
    return res.status(502).json({
      success: false,
      message: err.message,
    });
  }
});
