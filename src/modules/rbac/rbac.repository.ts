import { Prisma } from "@prisma/client";
import {
  prisma,
  DEFAULT_TRANSACTION_OPTIONS,
} from "../../database/prisma.client";
import { RoleQueryDto, AuditLogQueryDto } from "./rbac.dto";
import { getVietnamDayRange } from "../../common/helpers/date.helper";
import {
  VIETNAM_DATE_REGEX,
  ISO_DATE_REGEX,
} from "../../common/constants/date.constant";
import {
  calculatePaginationSkip,
  formatPaginationMeta,
} from "../../common/helpers/pagination.helper";
import { buildTsQuery } from "../../common/helpers/fts.helper";

export class RbacRepository {
  async findAllRoles(query: RoleQueryDto = {}) {
    const {
      search,
      sortBy = "createdAt",
      order = "asc",
      page = 1,
      limit = 20,
    } = query || {};

    const where: Prisma.RoleWhereInput = {
      ...(search
        ? {
            OR: [
              { name: { contains: search, mode: "insensitive" } },
              { description: { contains: search, mode: "insensitive" } },
            ],
          }
        : {}),
    };

    const {
      skip,
      take,
      page: safePage,
      limit: safeLimit,
    } = calculatePaginationSkip(page, limit);

    const [data, total] = await prisma.$transaction([
      prisma.role.findMany({
        where,
        include: {
          permissions: {
            include: {
              permission: true,
            },
          },
          _count: {
            select: { users: true },
          },
        },
        orderBy: { [sortBy]: order },
        skip,
        take,
      }),
      prisma.role.count({ where }),
    ]);

    return {
      data: data.map((role) => ({
        id: role.id,
        name: role.name,
        description: role.description,
        isSystem: role.isSystem,
        userCount: role._count.users,
        permissions: role.permissions.map((rp) => rp.permission),
        createdAt: role.createdAt,
        updatedAt: role.updatedAt,
      })),
      meta: formatPaginationMeta(safePage, safeLimit, total),
    };
  }

  async findRoleById(id: string) {
    const role = await prisma.role.findUnique({
      where: { id },
      include: {
        permissions: {
          include: {
            permission: true,
          },
        },
        _count: {
          select: { users: true },
        },
      },
    });

    if (!role) return null;

    return {
      id: role.id,
      name: role.name,
      description: role.description,
      isSystem: role.isSystem,
      userCount: role._count.users,
      permissions: role.permissions.map((rp) => rp.permission),
      createdAt: role.createdAt,
      updatedAt: role.updatedAt,
    };
  }

  async findRoleByName(name: string) {
    return prisma.role.findUnique({
      where: { name },
    });
  }

  async createRole(data: {
    name: string;
    description?: string;
    permissionIds?: string[];
  }) {
    return prisma.$transaction(async (tx) => {
      const role = await tx.role.create({
        data: {
          name: data.name,
          description: data.description,
          isSystem: false,
        },
      });

      if (data.permissionIds && data.permissionIds.length > 0) {
        await tx.rolePermission.createMany({
          data: data.permissionIds.map((permissionId) => ({
            roleId: role.id,
            permissionId,
          })),
          skipDuplicates: true,
        });
      }

      return role;
    }, DEFAULT_TRANSACTION_OPTIONS);
  }

  async updateRole(id: string, data: { name?: string; description?: string }) {
    return prisma.role.update({
      where: { id },
      data,
    });
  }

  async deleteRole(id: string) {
    return prisma.role.delete({
      where: { id },
    });
  }

  async findAllPermissions(query?: {
    page?: number;
    limit?: number;
    resource?: string;
  }) {
    const where: Prisma.PermissionWhereInput = {
      ...(query?.resource ? { resource: query.resource } : {}),
    };

    if (query?.page !== undefined || query?.limit !== undefined) {
      const {
        skip,
        take,
        page: safePage,
        limit: safeLimit,
      } = calculatePaginationSkip(query.page, query.limit, 50);
      const [data, total] = await prisma.$transaction([
        prisma.permission.findMany({
          where,
          orderBy: [{ resource: "asc" }, { action: "asc" }],
          skip,
          take,
        }),
        prisma.permission.count({ where }),
      ]);
      return {
        data,
        meta: formatPaginationMeta(safePage, safeLimit, total),
      };
    }

    return prisma.permission.findMany({
      where,
      take: 100,
      orderBy: [{ resource: "asc" }, { action: "asc" }],
    });
  }

  async findPermissionsByIds(ids: string[]) {
    return prisma.permission.findMany({
      where: { id: { in: ids } },
    });
  }

  async findPermissionByName(name: string) {
    return prisma.permission.findUnique({
      where: { name },
    });
  }

  async syncRolePermissions(roleId: string, permissionIds: string[]) {
    return prisma.$transaction(async (tx) => {
      await tx.rolePermission.deleteMany({
        where: { roleId },
      });

      if (permissionIds.length > 0) {
        await tx.rolePermission.createMany({
          data: permissionIds.map((permissionId) => ({
            roleId,
            permissionId,
          })),
          skipDuplicates: true,
        });
      }

      return tx.role.findUnique({
        where: { id: roleId },
        include: {
          permissions: {
            include: {
              permission: true,
            },
          },
        },
      });
    }, DEFAULT_TRANSACTION_OPTIONS);
  }

  async addPermissionToRole(roleId: string, permissionId: string) {
    return prisma.rolePermission.upsert({
      where: {
        roleId_permissionId: {
          roleId,
          permissionId,
        },
      },
      update: {},
      create: {
        roleId,
        permissionId,
      },
    });
  }

  async removePermissionFromRole(roleId: string, permissionId: string) {
    return prisma.rolePermission.deleteMany({
      where: {
        roleId,
        permissionId,
      },
    });
  }

  async createAuditLog(data: {
    actorId?: string;
    action: string;
    targetType: string;
    targetId: string;
    details?: Record<string, unknown> | null;
    ipAddress?: string;
    userAgent?: string;
  }) {
    return prisma.auditLog.create({
      data: {
        actorId: data.actorId,
        action: data.action,
        targetType: data.targetType,
        targetId: data.targetId,
        details: data.details
          ? (data.details as Prisma.InputJsonObject)
          : Prisma.DbNull,
        ipAddress: data.ipAddress,
        userAgent: data.userAgent,
      },
    });
  }

  async findAllAuditLogs(query: AuditLogQueryDto = {}) {
    const {
      search,
      actorId,
      action,
      targetType,
      targetId,
      startDate,
      endDate,
      page = 1,
      limit = 20,
    } = query || {};

    const createdAtFilter: Prisma.DateTimeFilter = {};
    if (startDate) {
      if (
        VIETNAM_DATE_REGEX.test(startDate) ||
        ISO_DATE_REGEX.test(startDate)
      ) {
        try {
          createdAtFilter.gte = getVietnamDayRange(startDate).startOfDay;
        } catch {
          const parsedStart = new Date(startDate);
          if (!isNaN(parsedStart.getTime())) {
            createdAtFilter.gte = parsedStart;
          }
        }
      } else {
        const parsedStart = new Date(startDate);
        if (!isNaN(parsedStart.getTime())) {
          createdAtFilter.gte = parsedStart;
        }
      }
    }
    if (endDate) {
      if (VIETNAM_DATE_REGEX.test(endDate) || ISO_DATE_REGEX.test(endDate)) {
        try {
          createdAtFilter.lte = getVietnamDayRange(endDate).endOfDay;
        } catch {
          const parsedEnd = new Date(endDate);
          if (!isNaN(parsedEnd.getTime())) {
            createdAtFilter.lte = parsedEnd;
          }
        }
      } else {
        const parsedEnd = new Date(endDate);
        if (!isNaN(parsedEnd.getTime())) {
          createdAtFilter.lte = parsedEnd;
        }
      }
    }

    const conditions: Prisma.AuditLogWhereInput[] = [];
    if (actorId) conditions.push({ actorId });
    if (action) conditions.push({ action });
    if (targetType) conditions.push({ targetType });
    if (targetId) conditions.push({ targetId });
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

    const {
      skip,
      take,
      page: safePage,
      limit: safeLimit,
    } = calculatePaginationSkip(page, limit);

    const [data, total] = await prisma.$transaction([
      prisma.auditLog.findMany({
        where,
        orderBy: { createdAt: "desc" },
        skip,
        take,
      }),
      prisma.auditLog.count({ where }),
    ]);

    return {
      data,
      meta: formatPaginationMeta(safePage, safeLimit, total),
    };
  }

  /**
   * Tìm kiếm Audit Logs bằng PostgreSQL Full-Text Search (tsvector, tsquery & GIN index)
   * Tự động xếp hạng độ tương đồng bằng hàm ts_rank
   */
  async searchAuditLogsFts(query: AuditLogQueryDto) {
    const search = query.search?.trim();
    if (!search) {
      return this.findAllAuditLogs(query);
    }

    const tsQuery = buildTsQuery(search, "prefix");
    if (!tsQuery) {
      return this.findAllAuditLogs(query);
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
    if (query.startDate) {
      const start = new Date(query.startDate);
      if (!isNaN(start.getTime())) {
        whereConditions.push(Prisma.sql`a.created_at >= ${start}`);
      }
    }
    if (query.endDate) {
      const end = new Date(query.endDate);
      if (!isNaN(end.getTime())) {
        end.setHours(23, 59, 59, 999);
        whereConditions.push(Prisma.sql`a.created_at <= ${end}`);
      }
    }

    const whereClause = Prisma.sql`WHERE ${Prisma.join(whereConditions, " AND ")}`;

    const [rawLogs, countResult] = await prisma.$transaction([
      prisma.$queryRaw<
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
      prisma.$queryRaw<Array<{ count: bigint }>>`
        SELECT COUNT(*)::bigint as count
        FROM audit_logs a
        ${whereClause}
      `,
    ]);

    const total = Number(countResult[0]?.count ?? 0);
    const data = rawLogs.map((l) => ({
      id: l.id,
      actorId: l.actor_id,
      action: l.action,
      targetType: l.target_type,
      targetId: l.target_id,
      details: l.details,
      ipAddress: l.ip_address,
      userAgent: l.user_agent,
      createdAt: l.created_at,
    }));

    return {
      data,
      meta: formatPaginationMeta(safePage, safeLimit, total),
    };
  }
}

export const rbacRepository = new RbacRepository();
