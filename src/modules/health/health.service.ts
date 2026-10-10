import IORedis from "ioredis";
import { envConfig } from "../../config/env.config";
import { HealthRepository, healthRepository } from "./health.repository";
import {
  HealthStatusDto,
  LivenessStatusDto,
  ReadinessResponseDto,
  CheckItemResult,
} from "./health.dto";

export class HealthService {
  private healthRedisClient: IORedis | null = null;

  constructor(
    private readonly repository: HealthRepository = healthRepository,
  ) {}

  private getHealthRedisClient(): IORedis | null {
    if (!envConfig.redis.enabled) return null;
    if (!this.healthRedisClient) {
      this.healthRedisClient = new IORedis({
        host: envConfig.redis.host,
        port: envConfig.redis.port,
        password: envConfig.redis.password,
        connectTimeout: 2000,
        lazyConnect: true,
        maxRetriesPerRequest: 1,
        retryStrategy: () => 1000,
      });
      this.healthRedisClient.on("error", () => {});
      this.healthRedisClient.connect().catch(() => {});
    }
    return this.healthRedisClient;
  }

  getHealth(): HealthStatusDto {
    return {
      status: "ok",
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      version: "1.0.0",
      environment: envConfig.nodeEnv,
    };
  }

  getLiveness(): LivenessStatusDto {
    return {
      status: "ok",
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
    };
  }

  async getReadiness(): Promise<{
    statusCode: number;
    data: ReadinessResponseDto;
  }> {
    const isProduction = envConfig.nodeEnv === "production";
    const startTime = Date.now();
    const checks: Record<string, CheckItemResult> = {};
    let overallHealthy = true;

    // Check 1: PostgreSQL Database connectivity
    try {
      const dbResult = await this.repository.pingDatabase();
      checks.database = {
        status: "healthy",
        ...(isProduction ? {} : { latencyMs: dbResult.latencyMs }),
      };
    } catch (err: any) {
      overallHealthy = false;
      checks.database = {
        status: "unhealthy",
        error: isProduction ? "Database connection error" : err.message,
      };
    }

    // Check 2: Redis connectivity
    if (envConfig.redis.enabled) {
      try {
        const redisStart = Date.now();
        const client = this.getHealthRedisClient();
        if (!client) {
          checks.redis = { status: "skipped" };
        } else {
          if (client.status !== "ready" && client.status !== "connecting") {
            await client.connect().catch(() => {});
          }
          await client.ping();
          checks.redis = {
            status: "healthy",
            ...(isProduction ? {} : { latencyMs: Date.now() - redisStart }),
          };
        }
      } catch (err: any) {
        checks.redis = {
          status: "unhealthy",
          error: isProduction ? "Redis ping failed" : err.message,
        };
      }
    } else {
      checks.redis = { status: "skipped" };
    }

    const statusCode = overallHealthy ? 200 : 503;

    const responseBody: ReadinessResponseDto = {
      status: overallHealthy ? "healthy" : "unhealthy",
      timestamp: new Date().toISOString(),
      checks,
    };

    if (!isProduction) {
      const memoryUsage = process.memoryUsage();
      responseBody.totalDurationMs = Date.now() - startTime;
      responseBody.metrics = {
        uptimeSeconds: Math.floor(process.uptime()),
        heapUsedMb:
          Math.round((memoryUsage.heapUsed / 1024 / 1024) * 100) / 100,
        heapTotalMb:
          Math.round((memoryUsage.heapTotal / 1024 / 1024) * 100) / 100,
        rssMb: Math.round((memoryUsage.rss / 1024 / 1024) * 100) / 100,
      };
    }

    return { statusCode, data: responseBody };
  }
}

export const healthService = new HealthService();
