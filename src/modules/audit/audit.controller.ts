import { Request, Response, NextFunction } from "express";
import { AuditService, auditService } from "./audit.service";
import {
  AuditLogQueryDto,
  AuditLogSummaryQueryDto,
  ExportAuditLogDto,
  ResourceAuditTrailQueryDto,
} from "./audit.dto";

export class AuditController {
  private readonly service: AuditService;

  constructor(service = auditService) {
    this.service = service;
  }

  // 1. Danh sách Audit Logs
  listLogs = async (
    req: Request<unknown, unknown, unknown, AuditLogQueryDto>,
    res: Response,
    next: NextFunction,
  ) => {
    try {
      const result = await this.service.listLogs(req.query);
      res.json({
        success: true,
        data: result.data,
        meta: result.meta,
      });
    } catch (error) {
      next(error);
    }
  };

  // 2. Lọc nhanh thay đổi cấu hình
  getConfigChanges = async (
    req: Request<unknown, unknown, unknown, AuditLogQueryDto>,
    res: Response,
    next: NextFunction,
  ) => {
    try {
      const result = await this.service.getConfigChanges(req.query);
      res.json({
        success: true,
        data: result.data,
        meta: result.meta,
      });
    } catch (error) {
      next(error);
    }
  };

  // 3. Lọc nhanh duyệt sự cố vi phạm
  getIncidentReviews = async (
    req: Request<unknown, unknown, unknown, AuditLogQueryDto>,
    res: Response,
    next: NextFunction,
  ) => {
    try {
      const result = await this.service.getIncidentReviews(req.query);
      res.json({
        success: true,
        data: result.data,
        meta: result.meta,
      });
    } catch (error) {
      next(error);
    }
  };

  // 4. Lấy timeline lịch sử của một tài nguyên
  getResourceAuditTrail = async (
    req: Request<
      { targetType: string; targetId: string },
      unknown,
      unknown,
      ResourceAuditTrailQueryDto
    >,
    res: Response,
    next: NextFunction,
  ) => {
    try {
      const { targetType, targetId } = req.params;
      const limit = req.query.limit !== undefined ? Number(req.query.limit) : undefined;
      const result = await this.service.getResourceAuditTrail(
        targetType,
        targetId,
        limit,
      );
      res.json({
        success: true,
        data: result,
      });
    } catch (error) {
      next(error);
    }
  };

  // 5. Thống kê KPI tổng quan
  getSummary = async (
    req: Request<unknown, unknown, unknown, AuditLogSummaryQueryDto>,
    res: Response,
    next: NextFunction,
  ) => {
    try {
      const result = await this.service.getSummary(req.query);
      res.json({
        success: true,
        data: result,
      });
    } catch (error) {
      next(error);
    }
  };

  // 6. Xuất báo cáo kiểm toán
  exportLogs = async (
    req: Request<unknown, unknown, unknown, ExportAuditLogDto>,
    res: Response,
    next: NextFunction,
  ) => {
    try {
      const result = await this.service.exportLogs(req.query);

      if (result.format === "csv") {
        res.setHeader("Content-Type", result.contentType);
        res.setHeader(
          "Content-Disposition",
          `attachment; filename="${result.fileName}"`,
        );
        res.send(result.data);
        return;
      }

      res.json({
        success: true,
        data: result.data,
        count: result.count,
      });
    } catch (error) {
      next(error);
    }
  };

  // 7. Chi tiết 1 bản ghi
  getLogDetail = async (
    req: Request<{ id: string }>,
    res: Response,
    next: NextFunction,
  ) => {
    try {
      const { id } = req.params;
      const result = await this.service.getLogDetail(id);
      res.json({
        success: true,
        data: result,
      });
    } catch (error) {
      next(error);
    }
  };
}

export const auditController = new AuditController();
