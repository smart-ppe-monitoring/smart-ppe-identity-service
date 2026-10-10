export interface HealthStatusDto {
  status: string;
  timestamp: string;
  uptime: number;
  version: string;
  environment: string;
}

export interface LivenessStatusDto {
  status: string;
  timestamp: string;
  uptime: number;
}

export interface CheckItemResult {
  status: "healthy" | "unhealthy" | "skipped";
  latencyMs?: number;
  error?: string;
}

export interface ReadinessResponseDto {
  status: "healthy" | "unhealthy";
  timestamp: string;
  checks: Record<string, CheckItemResult>;
  totalDurationMs?: number;
  metrics?: {
    uptimeSeconds: number;
    heapUsedMb: number;
    heapTotalMb: number;
    rssMb: number;
  };
}
