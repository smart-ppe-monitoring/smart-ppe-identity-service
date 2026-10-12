import { Prisma } from "@prisma/client";
import { prisma as identityPrisma } from "../../database/prisma.client";
import {
  AuditLogQueryDto,
  AuditLogItemDto,
  RecordAuditLogDto,
  AuditLogSummaryDto,
  AuditLogActorDto,
} from "./audit.dto";
import {
  AUDIT_CATEGORY_ACTIONS,
  SYSTEM_TARGET_ID,
} from "./audit.constant";
import {
  calculatePaginationSkip,
  formatPaginationMeta,
} from "../../common/helpers/pagination.helper";
import {
  VIETNAM_DATE_REGEX,
  ISO_DATE_REGEX,
} from "../../common/constants/date.constant";
import { getVietnamDayRange } from "../../common/helpers/date.helper";
import { buildTsQuery } from "../../common/helpers/fts.helper";

export class AuditRepository {
  private readonly db = identityPrisma;

  constructor(db = identityPrisma) {
    this.db = db;
  }

  // ── 1. Create Audit Log ────────────────────────────────────────────────────
  async createAuditLog(data: RecordAuditLogDto) {
    return this.db.auditLog.create({
      data: {
        actorId: data.actorId ?? null,
        action: data.action,
        targetType: data.targetType,
        targetId: data.targetId ?? SYSTEM_TARGET_ID,
        details: (data.details as Prisma.InputJsonValue) ?? undefined,
        ipAddress: data.ipAddress ?? null,
        userAgent: data.userAgent ?? null,
      },
    });
  }

  // ── 2. Find All Audit Logs (Pagination + Filtering) ────────────────────────
  async findAll(query: AuditLogQueryDto = {}): Promise<{
    data: AuditLogItemDto[];
    meta: ReturnType<typeof formatPaginationMeta>;
  }> {
    const {
      category,
      actorId,
      action,
      targetType,
      targetId,
      search,
      startDate,
      endDate,
      page = 1,
      limit = 20,
      sortBy = "createdAt",
      order = "desc",
    } = query;

    const conditions: Prisma.AuditLogWhereInput[] = [];

    // Filter by Category actions
    if (category && category !== "ALL" && AUDIT_CATEGORY_ACTIONS[category]) {
      const allowedActions = AUDIT_CATEGORY_ACTIONS[category];
      conditions.push({ action: { in: [...allowedActions] } });
    }

    if (actorId) conditions.push({ actorId });
    if (action) conditions.push({ action });
    if (targetType) conditions.push({ targetType });
    if (targetId) conditions.push({ targetId });

    // Date range filter
    const createdAtFilter = this.buildDateTimeFilter(startDate, endDate);
    if (Object.keys(createdAtFilter).length > 0) {
      conditions.push({ createdAt: createdAtFilter });
    }

    // Search filter
    if (search) {
      conditions.push({
        OR: [
          { action: { contains: search, mode: "insensitive" } },
          { targetType: { contains: search, mode: "insensitive" } },
          { ipAddress: { contains: search, mode: "insensitive" } },
          { userAgent: { contains: search, mode: "insensitive" } },
        ],
      });
    }

    const where: Prisma.AuditLogWhereInput =
      conditions.length > 0 ? { AND: conditions } : {};

    const {
      skip,
      take,
      page: safePage,
      limit: safeLimit,
    } = calculatePaginationSkip(page, limit);

    const [rawLogs, total] = await this.db.$transaction([
      this.db.auditLog.findMany({
        where,
        orderBy: { [sortBy]: order },
        skip,
        take,
      }),
      this.db.auditLog.count({ where }),
    ]);

    const enriched = await this.enrichActors(rawLogs);

    return {
      data: enriched,
      meta: formatPaginationMeta(safePage, safeLimit, total),
    };
  }

  // ── 3. Full-Text Search qua GIN index idx_audit_logs_fts ────────────────────
  async searchFts(query: AuditLogQueryDto = {}): Promise<{
    data: AuditLogItemDto[];
    meta: ReturnType<typeof formatPaginationMeta>;
  }> {
    const search = query.search?.trim();
    if (!search) {
      return this.findAll(query);
    }

    const tsQuery = buildTsQuery(search, "prefix");
    if (!tsQuery) {
      return this.findAll(query);
    }

    const {
      skip,
      take,
      page: safePage,
      limit: safeLimit,
    } = calculatePaginationSkip(query.page, query.limit);

    const whereConditions: Prisma.Sql[] = [
      Prisma.sql`to_tsvector('simple', coalesce(a.action, '') || ' ' || coalesce(a.target_type, '') || ' ' || coalesce(a.ip_address, '') || ' ' || coalesce(a.user_agent, '')) @@ to_tsquery('simple', ${tsQuery})`,
    ];

    if (query.category && query.category !== "ALL" && AUDIT_CATEGORY_ACTIONS[query.category]) {
      const allowedActions = AUDIT_CATEGORY_ACTIONS[query.category];
      whereConditions.push(
        Prisma.sql`a.action IN (${Prisma.join(allowedActions.map((act) => Prisma.sql`${act}`))})`,
      );
    }

    if (query.actorId) {
      whereConditions.push(Prisma.sql`a.actor_id = ${query.actorId}::uuid`);
    }
    if (query.action) {
      whereConditions.push(Prisma.sql`a.action = ${query.action}`);
    }
    if (query.targetType) {
      whereConditions.push(Prisma.sql`a.target_type = ${query.targetType}`);
    }
    if (query.targetId) {
      whereConditions.push(Prisma.sql`a.target_id = ${query.targetId}`);
    }
    const dateFilter = this.buildDateTimeFilter(query.startDate, query.endDate);
    if (dateFilter.gte) {
      whereConditions.push(Prisma.sql`a.created_at >= ${dateFilter.gte as Date}`);
    }
    if (dateFilter.lte) {
      whereConditions.push(Prisma.sql`a.created_at <= ${dateFilter.lte as Date}`);
    }

    const whereClause = Prisma.sql`WHERE ${Prisma.join(whereConditions, " AND ")}`;

    const [rawLogs, countResult] = await this.db.$transaction([
      this.db.$queryRaw<
        Array<{
          id: string;
          actor_id: string | null;
          action: string;
          target_type: string;
          target_id: string;
          details: unknown;
          ip_address: string | null;
          user_agent: string | null;
          created_at: Date;
          rank: number;
        }>
      >`
        SELECT
          a.id, a.actor_id, a.action, a.target_type, a.target_id,
          a.details, a.ip_address, a.user_agent, a.created_at,
          ts_rank(to_tsvector('simple', coalesce(a.action, '') || ' ' || coalesce(a.target_type, '') || ' ' || coalesce(a.ip_address, '') || ' ' || coalesce(a.user_agent, '')), to_tsquery('simple', ${tsQuery})) as rank
        FROM audit_logs a
        ${whereClause}
        ORDER BY rank DESC, a.created_at DESC
        OFFSET ${skip}
        LIMIT ${take}
      `,
      this.db.$queryRaw<Array<{ count: bigint }>>`
        SELECT COUNT(*)::bigint as count
        FROM audit_logs a
        ${whereClause}
      `,
    ]);

    const total = Number(countResult[0]?.count ?? 0);
    const mapped = rawLogs.map((l) => ({
      id: l.id,
      actorId: l.actor_id,
      action: l.action,
      targetType: l.target_type,
      targetId: l.target_id,
      details: (l.details as Record<string, unknown>) ?? null,
      ipAddress: l.ip_address,
      userAgent: l.user_agent,
      createdAt: l.created_at,
    }));

    const enriched = await this.enrichActors(mapped);

    return {
      data: enriched,
      meta: formatPaginationMeta(safePage, safeLimit, total),
    };
  }

  // ── 4. Find Audit Logs by Resource (Timeline) ──────────────────────────────
  async findByResource(
    targetType: string,
    targetId: string,
    limit = 50,
  ): Promise<AuditLogItemDto[]> {
    const rawLogs = await this.db.auditLog.findMany({
      where: {
        targetType,
        targetId,
      },
      orderBy: { createdAt: "desc" },
      take: Math.min(limit, 200),
    });

    return this.enrichActors(rawLogs);
  }

  // ── 5. Find Single Audit Log Detail ────────────────────────────────────────
  async findById(id: string): Promise<AuditLogItemDto | null> {
    const log = await this.db.auditLog.findUnique({
      where: { id },
    });

    if (!log) return null;

    const [enriched] = await this.enrichActors([log]);
    return enriched || null;
  }

  // ── 6. Get Audit Summary & KPI Metrics ─────────────────────────────────────
  async getSummary(
    startDate?: string,
    endDate?: string,
  ): Promise<AuditLogSummaryDto> {
    const createdAtFilter = this.buildDateTimeFilter(startDate, endDate);
    const where: Prisma.AuditLogWhereInput =
      Object.keys(createdAtFilter).length > 0
        ? { createdAt: createdAtFilter }
        : {};

    const [totalLogs, configCount, incidentReviewCount, accessControlCount, systemCount, topActionsRaw, topActorsRaw, recentLogsRaw] =
      await this.db.$transaction([
        this.db.auditLog.count({ where }),
        this.db.auditLog.count({
          where: {
            ...where,
            action: { in: [...AUDIT_CATEGORY_ACTIONS.CONFIG] },
          },
        }),
        this.db.auditLog.count({
          where: {
            ...where,
            action: { in: [...AUDIT_CATEGORY_ACTIONS.INCIDENT_REVIEW] },
          },
        }),
        this.db.auditLog.count({
          where: {
            ...where,
            action: { in: [...AUDIT_CATEGORY_ACTIONS.ACCESS_CONTROL] },
          },
        }),
        this.db.auditLog.count({
          where: {
            ...where,
            action: { in: [...AUDIT_CATEGORY_ACTIONS.SYSTEM] },
          },
        }),
        this.db.auditLog.groupBy({
          by: ["action"],
          where,
          _count: { action: true },
          orderBy: { _count: { action: "desc" } },
          take: 5,
        }),
        this.db.auditLog.groupBy({
          by: ["actorId"],
          where: {
            ...where,
            actorId: { not: null },
          },
          _count: { actorId: true },
          orderBy: { _count: { actorId: "desc" } },
          take: 5,
        }),
        this.db.auditLog.findMany({
          where,
          orderBy: { createdAt: "desc" },
          take: 5,
        }),
      ]);

    // Enrich actor names for topActors
    const actorIds = topActorsRaw
      .map((a) => a.actorId)
      .filter((id): id is string => typeof id === "string");

    const users = actorIds.length > 0
      ? await this.db.user.findMany({
          where: { id: { in: actorIds } },
          select: { id: true, fullName: true, email: true },
        })
      : [];

    const userMap = new Map(users.map((u) => [u.id, u.fullName || u.email]));

    const topActors = topActorsRaw.map((a) => {
      const count =
        typeof a._count === "object" && a._count !== null
          ? (a._count as { actorId?: number }).actorId ?? 0
          : 0;
      return {
        actorId: a.actorId,
        actorName: (a.actorId && userMap.get(a.actorId)) || a.actorId || "System/Unknown",
        count,
      };
    });

    const topActions = topActionsRaw.map((a) => {
      const count =
        typeof a._count === "object" && a._count !== null
          ? (a._count as { action?: number }).action ?? 0
          : 0;
      return {
        action: a.action,
        count,
      };
    });

    const recentActivity = await this.enrichActors(recentLogsRaw);

    return {
      totalLogs,
      categoryCounts: {
        config: configCount,
        incidentReview: incidentReviewCount,
        accessControl: accessControlCount,
        system: systemCount,
      },
      topActors,
      topActions,
      recentActivity,
    };
  }

  // ── 7. Find for Export (Max Rows Guard) ─────────────────────────────────────
  async findForExport(
    query: AuditLogQueryDto = {},
    maxRows = 5000,
  ): Promise<AuditLogItemDto[]> {
    const {
      category,
      actorId,
      action,
      targetType,
      targetId,
      search,
      startDate,
      endDate,
    } = query;

    const conditions: Prisma.AuditLogWhereInput[] = [];

    if (category && category !== "ALL" && AUDIT_CATEGORY_ACTIONS[category]) {
      conditions.push({ action: { in: [...AUDIT_CATEGORY_ACTIONS[category]] } });
    }
    if (actorId) conditions.push({ actorId });
    if (action) conditions.push({ action });
    if (targetType) conditions.push({ targetType });
    if (targetId) conditions.push({ targetId });

    const createdAtFilter = this.buildDateTimeFilter(startDate, endDate);
    if (Object.keys(createdAtFilter).length > 0) {
      conditions.push({ createdAt: createdAtFilter });
    }

    if (search) {
      conditions.push({
        OR: [
          { action: { contains: search, mode: "insensitive" } },
          { targetType: { contains: search, mode: "insensitive" } },
          { ipAddress: { contains: search, mode: "insensitive" } },
          { userAgent: { contains: search, mode: "insensitive" } },
        ],
      });
    }

    const where: Prisma.AuditLogWhereInput =
      conditions.length > 0 ? { AND: conditions } : {};

    const rawLogs = await this.db.auditLog.findMany({
      where,
      orderBy: { createdAt: "desc" },
      take: maxRows,
    });

    return this.enrichActors(rawLogs);
  }

  // ── 8. Batch Actor Profile Enrichment (Anti-N+1) ───────────────────────────
  private async enrichActors(
    rawLogs: Array<{
      id: string;
      actorId: string | null;
      action: string;
      targetType: string;
      targetId: string;
      details: unknown;
      ipAddress: string | null;
      userAgent: string | null;
      createdAt: Date;
    }>,
  ): Promise<AuditLogItemDto[]> {
    if (rawLogs.length === 0) return [];

    const actorIds = Array.from(
      new Set(
        rawLogs
          .map((l) => l.actorId)
          .filter((id): id is string => typeof id === "string"),
      ),
    );

    let actorMap = new Map<string, AuditLogActorDto>();
    if (actorIds.length > 0) {
      const users = await this.db.user.findMany({
        where: { id: { in: actorIds } },
        select: {
          id: true,
          email: true,
          fullName: true,
          role: {
            select: { name: true },
          },
        },
      });

      actorMap = new Map(
        users.map((u) => [
          u.id,
          {
            id: u.id,
            email: u.email,
            fullName: u.fullName,
            roleName: u.role?.name,
          },
        ]),
      );
    }

    return rawLogs.map((l) => ({
      id: l.id,
      actorId: l.actorId,
      actor: l.actorId ? actorMap.get(l.actorId) || null : null,
      action: l.action,
      targetType: l.targetType,
      targetId: l.targetId,
      details: (l.details as Record<string, unknown>) ?? null,
      ipAddress: l.ipAddress,
      userAgent: l.userAgent,
      createdAt: l.createdAt.toISOString(),
    }));
  }

  // ── 9. Date Time Filter Helper (Vietnam Timezone Aware) ────────────────────
  private buildDateTimeFilter(
    startDate?: string,
    endDate?: string,
  ): Prisma.DateTimeFilter {
    const createdAtFilter: Prisma.DateTimeFilter = {};
    if (startDate) {
      if (
        VIETNAM_DATE_REGEX.test(startDate) ||
        ISO_DATE_REGEX.test(startDate)
      ) {
        try {
          createdAtFilter.gte = getVietnamDayRange(startDate).startOfDay;
        } catch {
          const parsed = new Date(startDate);
          if (!isNaN(parsed.getTime())) createdAtFilter.gte = parsed;
        }
      } else {
        const parsed = new Date(startDate);
        if (!isNaN(parsed.getTime())) createdAtFilter.gte = parsed;
      }
    }
    if (endDate) {
      if (
        VIETNAM_DATE_REGEX.test(endDate) ||
        ISO_DATE_REGEX.test(endDate)
      ) {
        try {
          createdAtFilter.lte = getVietnamDayRange(endDate).endOfDay;
        } catch {
          const parsed = new Date(endDate);
          if (!isNaN(parsed.getTime())) createdAtFilter.lte = parsed;
        }
      } else {
        const parsed = new Date(endDate);
        if (!isNaN(parsed.getTime())) createdAtFilter.lte = parsed;
      }
    }
    return createdAtFilter;
  }

  /**
   * 8. Tra cứu các bản ghi AuditLog liên kết với traceId (Distributed Tracing)
   */
  async findByTraceId(traceId: string, limit: number = 50): Promise<AuditLogItemDto[]> {
    try {
      const logs = await this.db.auditLog.findMany({
        where: {
          details: {
            path: ["traceId"],
            equals: traceId,
          },
        },
        orderBy: { createdAt: "asc" },
        take: limit,
      });

      return logs.map((log) => ({
        id: log.id,
        actorId: log.actorId,
        actor: null,
        action: log.action,
        targetType: log.targetType,
        targetId: log.targetId,
        details: log.details as Record<string, unknown> | null,
        ipAddress: log.ipAddress,
        userAgent: log.userAgent,
        createdAt: log.createdAt.toISOString(),
      }));
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      console.warn(`[AuditRepository] Lỗi tra cứu audit logs theo traceId ${traceId}:`, message);
      return [];
    }
  }
}

export const auditRepository = new AuditRepository();
