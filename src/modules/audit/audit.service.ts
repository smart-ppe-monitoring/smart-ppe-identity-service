import { AuditRepository, auditRepository } from "./audit.repository";
import {
  AuditLogQueryDto,
  AuditLogItemDto,
  RecordAuditLogDto,
  AuditLogSummaryDto,
  ExportAuditLogDto,
} from "./audit.dto";
import { AUDIT_CATEGORY } from "./audit.constant";
import { AppError } from "../../common/errors/app-error";
import { ERROR_CODE } from "../../common/errors/error-code";
import { formatPaginationMeta } from "../../common/helpers/pagination.helper";

export class AuditService {
  private readonly repository: AuditRepository;

  constructor(repository = auditRepository) {
    this.repository = repository;
  }

  // ── 1. Danh sách Audit Logs (FTS / Filter) ──────────────────────────────────
  async listLogs(query: AuditLogQueryDto): Promise<{
    data: AuditLogItemDto[];
    meta: ReturnType<typeof formatPaginationMeta>;
  }> {
    if (query.search?.trim()) {
      return this.repository.searchFts(query);
    }
    return this.repository.findAll(query);
  }

  // ── 2. Lọc nhanh các thay đổi Cấu hình (Config Changes) ─────────────────────
  async getConfigChanges(query: AuditLogQueryDto) {
    const enrichedQuery: AuditLogQueryDto = {
      ...query,
      category: AUDIT_CATEGORY.CONFIG,
    };
    return this.listLogs(enrichedQuery);
  }

  // ── 3. Lọc nhanh các thao tác Review Sự cố (Incident Reviews) ──────────────
  async getIncidentReviews(query: AuditLogQueryDto) {
    const enrichedQuery: AuditLogQueryDto = {
      ...query,
      category: AUDIT_CATEGORY.INCIDENT_REVIEW,
    };
    return this.listLogs(enrichedQuery);
  }

  // ── 4. Lấy Timeline Kiểm toán của một Resource cụ thể ──────────────────────
  async getResourceAuditTrail(
    targetType: string,
    targetId: string,
    limit?: number,
  ): Promise<AuditLogItemDto[]> {
    return this.repository.findByResource(targetType, targetId, limit);
  }

  // ── 5. Chi tiết một bản ghi Audit Log ──────────────────────────────────────
  async getLogDetail(id: string): Promise<AuditLogItemDto> {
    const log = await this.repository.findById(id);
    if (!log) {
      throw new AppError(
        "Không tìm thấy bản ghi nhật ký kiểm toán",
        404,
        ERROR_CODE.NOT_FOUND,
      );
    }
    return log;
  }

  // ── 6. Thống kê KPI Tổng quan (Audit Summary) ──────────────────────────────
  async getSummary(query?: {
    startDate?: string;
    endDate?: string;
  }): Promise<AuditLogSummaryDto> {
    return this.repository.getSummary(query?.startDate, query?.endDate);
  }

  // ── 7. Xuất Báo cáo Kiểm toán (CSV / JSON) ─────────────────────────────────
  async exportLogs(dto: ExportAuditLogDto): Promise<{
    format: string;
    contentType: string;
    fileName: string;
    data: string | AuditLogItemDto[];
    count: number;
  }> {
    const logs = await this.repository.findForExport(dto);
    const format = dto.format || "csv";
    const timestamp = Date.now();

    if (format === "json") {
      return {
        format: "json",
        contentType: "application/json; charset=utf-8",
        fileName: `audit_logs_${timestamp}.json`,
        data: logs,
        count: logs.length,
      };
    }

    // Format CSV chuẩn RFC 4180
    const csvContent = this.formatLogsToCsv(logs);
    return {
      format: "csv",
      contentType: "text/csv; charset=utf-8",
      fileName: `audit_logs_${timestamp}.csv`,
      data: csvContent,
      count: logs.length,
    };
  }

  // ── 8. Ghi Audit Log Tiện ích (Non-blocking) ───────────────────────────────
  async recordLog(dto: RecordAuditLogDto) {
    try {
      return await this.repository.createAuditLog(dto);
    } catch (error) {
      console.warn(
        "[AuditService] Ghi audit log không thành công (non-blocking):",
        error,
      );
      return null;
    }
  }

  // ── Helper: Format CSV RFC 4180 ────────────────────────────────────────────
  private formatLogsToCsv(logs: AuditLogItemDto[]): string {
    const headers = [
      "ID",
      "Thời gian",
      "Hành động",
      "Loại tài nguyên",
      "Mã tài nguyên",
      "Mã người dùng",
      "Tên người dùng",
      "Email",
      "Vai trò",
      "Địa chỉ IP",
      "Chi tiết (JSON)",
    ];

    const escapeCsvField = (value: unknown): string => {
      if (value === null || value === undefined) return '""';
      let str = typeof value === "object" ? JSON.stringify(value) : String(value);
      // Neutralize formula injection (CWE-1236) if string begins with =, +, -, @, \t, \r
      if (/^[=+\-@\t\r]/.test(str)) {
        str = `'${str}`;
      }
      // Double internal quotes
      str = str.replace(/"/g, '""');
      return `"${str}"`;
    };

    const rows = logs.map((log) => [
      escapeCsvField(log.id),
      escapeCsvField(log.createdAt),
      escapeCsvField(log.action),
      escapeCsvField(log.targetType),
      escapeCsvField(log.targetId),
      escapeCsvField(log.actorId || "N/A"),
      escapeCsvField(log.actor?.fullName || "N/A"),
      escapeCsvField(log.actor?.email || "N/A"),
      escapeCsvField(log.actor?.roleName || "N/A"),
      escapeCsvField(log.ipAddress || "N/A"),
      escapeCsvField(log.details || {}),
    ]);

    const csvLines = [headers.join(","), ...rows.map((r) => r.join(","))];
    // BOM for UTF-8 Excel support
    return "\uFEFF" + csvLines.join("\r\n");
  }

  // ── 7. Lấy danh sách Audit Logs theo Trace ID ──────────────────────────────
  async getAuditLogsByTraceId(
    traceId: string,
    limit?: number,
  ): Promise<AuditLogItemDto[]> {
    return this.repository.findByTraceId(traceId, limit);
  }
}

export const auditService = new AuditService();
