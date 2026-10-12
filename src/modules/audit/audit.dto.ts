import {
  AuditAction,
  AuditCategory,
  AuditExportFormat,
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
  totalLogs: number;
  categoryCounts: {
    config: number;
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
