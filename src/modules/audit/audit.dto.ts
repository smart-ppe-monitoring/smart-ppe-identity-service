import {
  AuditAction,
  AuditCategory,
  AuditExportFormat,
  AuditLogStatus,
  AuditScope,
  AuditTargetType,
} from "./audit.constant";

export interface AuditLogActorDto {
  id: string;
  email: string | null;
  fullName: string | null;
  roleName?: string;
}

export interface AuditLogSummaryQueryDto {
  startDate?: string;
  endDate?: string;
}

export interface ResourceAuditTrailQueryDto {
  limit?: number;
}

export interface AuditLogItemDto {
  id: string;
  actorId: string | null;
  actor: AuditLogActorDto | null;
  action: string;
  status: AuditLogStatus;
  targetType: string;
  targetId: string;
  details: Record<string, unknown> | null;
  ipAddress: string | null;
  userAgent: string | null;
  createdAt: string;
}

export interface AuditLogQueryDto {
  category?: AuditCategory;
  actorId?: string;
  action?: string;
  status?: AuditLogStatus;
  targetType?: string;
  targetId?: string;
  search?: string;
  startDate?: string;
  endDate?: string;
  page?: number;
  limit?: number;
  sortBy?: "createdAt" | "action" | "targetType";
  order?: "asc" | "desc";
}

export interface AuditLogSummaryDto {
  scope: AuditScope;
  totalLogs: number;
  successCount: number;
  failedCount: number;
  successRate: number | null;
  categoryCounts: {
    config: number;
    /**
     * @deprecated Incident review logs belong to `smart-ppe-incident-service` under Database-per-Service isolation.
     */
    incidentReview: number;
    accessControl: number;
    system: number;
  };
  topActors: Array<{
    actorId: string | null;
    actorName: string;
    count: number;
  }>;
  topActions: Array<{
    action: string;
    count: number;
  }>;
  recentActivity: AuditLogItemDto[];
}

export interface RecordAuditLogDto {
  actorId?: string | null;
  action: AuditAction | string;
  targetType: AuditTargetType | string;
  targetId: string;
  details?: Record<string, unknown> | null;
  ipAddress?: string | null;
  userAgent?: string | null;
}

export interface ExportAuditLogDto extends AuditLogQueryDto {
  format?: AuditExportFormat;
}
