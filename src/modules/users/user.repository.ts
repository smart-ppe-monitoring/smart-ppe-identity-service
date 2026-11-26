import { Prisma } from "@prisma/client";
import { prisma } from "../../database/prisma.client";
import { ROLES } from "../../common/constants/role.constant";
import { PERMISSIONS } from "../../common/constants/permission.constant";
import { SYSTEM_TARGET_ID } from "../../common/constants/audit-log.constant";
import { UserQueryDto, UserSummaryDto } from "./user.dto";
import {
  calculatePaginationSkip,
  formatPaginationMeta,
} from "../../common/helpers/pagination.helper";
import { buildTsQuery } from "../../common/helpers/fts.helper";

const userSelect = {
  id: true,
  email: true,
  fullName: true,
  avatarUrl: true,
  phoneNumber: true,
  isActive: true,
  twoFactorEnabled: true,
  failedLoginAttempts: true,
  lockedUntil: true,
  mustChangePassword: true,
  deletedAt: true,
  roleId: true,
  siteIds: true,
  role: {
    select: {
      id: true,
      name: true,
    },
  },
  createdAt: true,
  updatedAt: true,
} satisfies Prisma.UserSelect;

// MED-02 Fix: userSummarySelect không bao gồm metadata khóa tài khoản (failedLoginAttempts, lockedUntil)
const userSummarySelect = {
  id: true,
  email: true,
  fullName: true,
  avatarUrl: true,
  phoneNumber: true,
  isActive: true,
  twoFactorEnabled: true,
  mustChangePassword: true,
  deletedAt: true,
  roleId: true,
  siteIds: true,
  role: {
    select: {
      id: true,
      name: true,
    },
  },
  createdAt: true,
  updatedAt: true,
} satisfies Prisma.UserSelect;

const sessionSelect = {
  id: true,
  userAgent: true,
  ipAddress: true,
  expiresAt: true,
  createdAt: true,
} satisfies Prisma.RefreshTokenSelect;

const deviceSelect = {
  id: true,
  deviceName: true,
  ipAddress: true,
  lastLoginAt: true,
  createdAt: true,
} satisfies Prisma.UserDeviceSelect;

export class UserRepository {
  private readonly db: typeof prisma;

  constructor(dbClient?: typeof prisma) {
    this.db = dbClient || prisma;
  }

  async findAll(query: UserQueryDto = {}) {
    const {
      search,
      email,
      fullName,
      roleName,
      siteId,
      excludeSiteId,
      isActive,
      isDeleted,
      twoFactorEnabled,
      isLocked,
      sortBy = "createdAt",
      order = "desc",
      page = 1,
      limit = 20,
    } = query || {};

    const conditions: Prisma.UserWhereInput[] = [
      isDeleted === true ? { deletedAt: { not: null } } : { deletedAt: null },
    ];

    if (email) {
      conditions.push({ email: { contains: email, mode: "insensitive" } });
    }
    if (fullName) {
      conditions.push({
        fullName: { contains: fullName, mode: "insensitive" },
      });
    }
    if (isActive !== undefined) {
      conditions.push({ isActive });
    }
    if (twoFactorEnabled !== undefined) {
      conditions.push({ twoFactorEnabled });
    }
    if (isLocked !== undefined) {
      const now = new Date();
      if (isLocked) {
        conditions.push({
          OR: [{ isActive: false }, { lockedUntil: { gt: now } }],
        });
      } else {
        conditions.push({
          AND: [
            { isActive: true },
            { OR: [{ lockedUntil: null }, { lockedUntil: { lte: now } }] },
          ],
        });
      }
    }
    if (roleName) {
      conditions.push({ role: { name: roleName } });
    }
    if (siteId) {
      conditions.push({ siteIds: { has: siteId } });
    }
    if (excludeSiteId) {
      conditions.push({ NOT: { siteIds: { has: excludeSiteId } } });
    }
    if (search) {
      conditions.push({
        OR: [
          { fullName: { contains: search, mode: "insensitive" } },
          { email: { contains: search, mode: "insensitive" } },
          { phoneNumber: { contains: search, mode: "insensitive" } },
        ],
      });
    }

    const where: Prisma.UserWhereInput = {
      AND: conditions,
    };

    const {
      skip,
      take,
      page: safePage,
      limit: safeLimit,
    } = calculatePaginationSkip(page, limit);

    const SORT_MAP: Record<string, Prisma.UserOrderByWithRelationInput> = {
      createdAt: { createdAt: order },
      email: { email: order },
      fullName: { fullName: order },
    };
    const orderBy = SORT_MAP[sortBy] ?? { createdAt: order };

    const [data, total] = await this.db.$transaction([
      this.db.user.findMany({
        where,
        select: userSummarySelect,
        orderBy,
        skip,
        take,
      }),
      this.db.user.count({ where }),
    ]);

    return {
      data,
      meta: formatPaginationMeta(safePage, safeLimit, total),
    };
  }

  /**
   * Tìm kiếm người dùng bằng PostgreSQL Full-Text Search (tsvector, tsquery & GIN index)
   * Tự động xếp hạng độ tương đồng bằng hàm ts_rank
   */
  async searchFts(query: UserQueryDto) {
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
      Prisma.sql`to_tsvector('simple', coalesce(u.full_name, '') || ' ' || coalesce(u.email, '') || ' ' || coalesce(u.phone_number, '')) @@ to_tsquery('simple', ${tsQuery})`,
    ];

    if (query.isDeleted === true) {
      whereConditions.push(Prisma.sql`u.deleted_at IS NOT NULL`);
    } else {
      whereConditions.push(Prisma.sql`u.deleted_at IS NULL`);
    }

    if (query.isActive !== undefined) {
      whereConditions.push(Prisma.sql`u.is_active = ${query.isActive}`);
    }

    if (query.twoFactorEnabled !== undefined) {
      whereConditions.push(
        Prisma.sql`u.two_factor_enabled = ${query.twoFactorEnabled}`,
      );
    }

    if (query.isLocked !== undefined) {
      const now = new Date();
      if (query.isLocked) {
        whereConditions.push(
          Prisma.sql`(u.is_active = false OR (u.locked_until IS NOT NULL AND u.locked_until > (${now}::timestamptz AT TIME ZONE 'UTC')))`,
        );
      } else {
        whereConditions.push(
          Prisma.sql`(u.is_active = true AND (u.locked_until IS NULL OR u.locked_until <= (${now}::timestamptz AT TIME ZONE 'UTC')))`,
        );
      }
    }

    if (query.roleName) {
      whereConditions.push(Prisma.sql`r.name = ${query.roleName}`);
    }

    if (query.siteId) {
      whereConditions.push(
        Prisma.sql`u.site_ids @> ARRAY[${query.siteId}]::text[]`,
      );
    }

    if (query.excludeSiteId) {
      whereConditions.push(
        Prisma.sql`NOT (coalesce(u.site_ids, ARRAY[]::text[]) @> ARRAY[${query.excludeSiteId}]::text[])`,
      );
    }

    if (query.email) {
      whereConditions.push(
        Prisma.sql`u.email ILIKE ${"%" + query.email + "%"}`,
      );
    }

    if (query.fullName) {
      whereConditions.push(
        Prisma.sql`u.full_name ILIKE ${"%" + query.fullName + "%"}`,
      );
    }

    const whereClause = Prisma.sql`WHERE ${Prisma.join(whereConditions, " AND ")}`;

    const [rawUsers, countResult] = await this.db.$transaction([
      this.db.$queryRaw<
        Array<{
          id: string;
          email: string | null;
          full_name: string | null;
          avatar_url: string | null;
          phone_number: string | null;
          role_id: string;
          role_name: string;
          site_ids: string[] | null;
          is_active: boolean;
          two_factor_enabled: boolean;
          must_change_password: boolean;
          failed_login_attempts: number;
          locked_until: Date | null;
          deleted_at: Date | null;
          created_at: Date;
          updated_at: Date;
          rank: number;
        }>
      >`
        SELECT
          u.id, u.email, u.full_name, u.avatar_url, u.phone_number,
          u.role_id, r.name as role_name, u.site_ids, u.is_active, u.two_factor_enabled,
          u.must_change_password, u.failed_login_attempts, u.locked_until,
          u.deleted_at, u.created_at, u.updated_at,
          ts_rank(to_tsvector('simple', coalesce(u.full_name, '') || ' ' || coalesce(u.email, '') || ' ' || coalesce(u.phone_number, '')), to_tsquery('simple', ${tsQuery})) as rank
        FROM users u
        LEFT JOIN roles r ON u.role_id = r.id
        ${whereClause}
        ORDER BY rank DESC, u.created_at DESC
        OFFSET ${skip}
        LIMIT ${take}
      `,
      this.db.$queryRaw<Array<{ count: bigint }>>`
        SELECT COUNT(*)::bigint as count
        FROM users u
        LEFT JOIN roles r ON u.role_id = r.id
        ${whereClause}
      `,
    ]);

    const total = Number(countResult[0]?.count ?? 0);
    const data = rawUsers.map((u) => ({
      id: u.id,
      email: u.email,
      fullName: u.full_name,
      avatarUrl: u.avatar_url,
      phoneNumber: u.phone_number,
      roleId: u.role_id,
      role: { id: u.role_id, name: u.role_name },
      siteIds: Array.isArray(u.site_ids) ? u.site_ids : [],
      isActive: u.is_active,
      twoFactorEnabled: u.two_factor_enabled,
      mustChangePassword: u.must_change_password,
      failedLoginAttempts: u.failed_login_attempts,
      lockedUntil: u.locked_until,
      deletedAt: u.deleted_at,
      createdAt: u.created_at,
      updatedAt: u.updated_at,
    }));

    return {
      data,
      meta: formatPaginationMeta(safePage, safeLimit, total),
    };
  }

  /**
   * Tổng hợp số liệu KPI người dùng chưa bị xóa mềm trực tiếp trên database.
   */
  async getSummary(): Promise<UserSummaryDto> {
    const now = new Date();

    const [kpiRows, roleRows] = await this.db.$transaction([
      this.db.$queryRaw<
        Array<{
          total: bigint;
          active: bigint;
          two_factor: bigint;
          locked: bigint;
        }>
      >`
        SELECT
          COUNT(*)::bigint AS total,
          COUNT(*) FILTER (WHERE is_active = true AND (locked_until IS NULL OR locked_until <= (${now}::timestamptz AT TIME ZONE 'UTC')))::bigint AS active,
          COUNT(*) FILTER (WHERE two_factor_enabled = true)::bigint AS two_factor,
          COUNT(*) FILTER (WHERE is_active = false OR (locked_until IS NOT NULL AND locked_until > (${now}::timestamptz AT TIME ZONE 'UTC')))::bigint AS locked
        FROM users
        WHERE deleted_at IS NULL
      `,
      this.db.$queryRaw<
        Array<{
          role_name: string;
          count: bigint;
        }>
      >`
        SELECT
          r.name AS role_name,
          COUNT(*)::bigint AS count
        FROM users u
        INNER JOIN roles r ON u.role_id = r.id
        WHERE u.deleted_at IS NULL
        GROUP BY r.name
      `,
    ]);

    const summary = kpiRows[0];
    const byRole: Record<string, number> = {};
    for (const row of roleRows) {
      if (row.role_name) {
        byRole[row.role_name] = Number(row.count ?? 0);
      }
    }

    return {
      total: Number(summary?.total ?? 0),
      active: Number(summary?.active ?? 0),
      twoFactor: Number(summary?.two_factor ?? 0),
      locked: Number(summary?.locked ?? 0),
      byRole,
    };
  }

  findById(id: string) {
    return prisma.user.findFirst({
      where: { id, deletedAt: null },
      select: userSelect,
    });
  }

  findUserStateById(id: string) {
    return prisma.user.findUnique({
      where: { id },
      select: {
        id: true,
        isActive: true,
        deletedAt: true,
        roleId: true,
        siteIds: true,
        mustChangePassword: true,
        role: { select: { name: true } },
      },
    });
  }

  findByEmail(email: string) {
    return prisma.user.findFirst({
      where: { email, deletedAt: null },
      select: userSelect,
    });
  }

  findUserWithRole(id: string) {
    return prisma.user.findUnique({
      where: { id },
      select: {
        id: true,
        email: true,
        roleId: true,
        isActive: true,
        deletedAt: true,
        role: { select: { id: true, name: true } },
      },
    });
  }

  assignRole(userId: string, roleId: string) {
    return prisma.user.update({
      where: { id: userId },
      data: { roleId },
      include: { role: true },
    });
  }

  getActiveUsersChunk(take = 500, cursorId?: string) {
    return prisma.user.findMany({
      where: { isActive: true, deletedAt: null },
      select: { id: true },
      orderBy: { id: "asc" },
      take,
      ...(cursorId ? { skip: 1, cursor: { id: cursorId } } : {}),
    });
  }

  findActiveUsersByIds(ids: string[]) {
    return prisma.user.findMany({
      where: { id: { in: ids }, isActive: true, deletedAt: null },
      select: { id: true, email: true },
    });
  }

  findUserEmailById(userId: string) {
    return prisma.user.findUnique({
      where: { id: userId },
      select: { email: true },
    });
  }

  findRoleById(id: string) {
    return prisma.role.findUnique({
      where: { id },
      select: { id: true, name: true },
    });
  }

  create(data: {
    email?: string;
    passwordHash?: string;
    fullName?: string;
    avatarUrl?: string;
    phoneNumber?: string;
    roleId: string;
    siteIds?: string[];
    isActive?: boolean;
    mustChangePassword?: boolean;
  }) {
    return prisma.user.create({
      data: {
        email: data.email,
        password: data.passwordHash,
        fullName: data.fullName,
        avatarUrl: data.avatarUrl,
        phoneNumber: data.phoneNumber,
        roleId: data.roleId,
        siteIds: data.siteIds || [],
        isActive: data.isActive,
        mustChangePassword: data.mustChangePassword ?? false,
      },
      select: userSelect,
    });
  }

  findWithDeleted(id: string) {
    return prisma.user.findUnique({
      where: { id },
      select: userSelect,
    });
  }

  restore(id: string) {
    return prisma.user.update({
      where: { id },
      data: {
        deletedAt: null,
        deletedBy: null,
        isActive: true,
      },
      select: userSelect,
    });
  }

  async adminResetPassword(
    id: string,
    passwordHash: string,
    mustChangePassword: boolean,
  ) {
    const [user] = await prisma.$transaction([
      prisma.user.update({
        where: { id },
        data: {
          password: passwordHash,
          mustChangePassword,
          failedLoginAttempts: 0,
          lockedUntil: null,
        },
        select: userSelect,
      }),
      prisma.refreshToken.deleteMany({
        where: { userId: id },
      }),
    ]);
    return user;
  }

  update(
    id: string,
    data: {
      isActive?: boolean;
      fullName?: string;
      phoneNumber?: string;
      siteIds?: string[];
    },
  ) {
    return prisma.user.update({
      where: { id },
      data,
      select: userSelect,
    });
  }

  assignSites(id: string, siteIds: string[]) {
    return prisma.user.update({
      where: { id },
      data: { siteIds },
      select: userSelect,
    });
  }

  /**
   * Đếm số lượng người dùng đang hoạt động theo vai trò bất kỳ.
   */
  async countActiveUsersByRole(roleName: string): Promise<number> {
    return prisma.user.count({
      where: {
        deletedAt: null,
        isActive: true,
        role: {
          name: roleName,
        },
      },
    });
  }

  /**
   * Đếm số lượng người dùng đang hoạt động có vai trò Quản trị viên hệ thống (mặc định ROLES.ADMIN).
   * Khắc phục SEC-06: Chỉ đếm tài khoản mang vai trò Admin thực tế, không tính gộp các vai trò
   * ủy quyền (Operator) để đảm bảo hàng rào Anti-lockout bảo vệ Admin duy nhất không bị vượt qua.
   */
  async countActiveAdmins(roleName: string = ROLES.ADMIN): Promise<number> {
    return prisma.user.count({
      where: {
        deletedAt: null,
        isActive: true,
        role: { name: roleName },
      },
    });
  }

  async softDelete(
    id: string,
    adminId: string,
    tombstone?: { email?: string; phoneNumber?: string | null },
  ) {
    const data: Prisma.UserUpdateInput = {
      deletedAt: new Date(),
      deletedBy: adminId,
      isActive: false,
      email:
        tombstone?.email !== undefined
          ? tombstone.email
          : `deleted_${Date.now()}_${id}@tombstone.local`,
      phoneNumber:
        tombstone?.phoneNumber !== undefined ? tombstone.phoneNumber : null,
    };

    return prisma.$transaction([
      prisma.user.update({
        where: { id },
        data,
      }),
      prisma.refreshToken.deleteMany({
        where: { userId: id },
      }),
    ]);
  }

  // ────── Session Management ──────

  findSessionsByUserId(userId: string) {
    return prisma.refreshToken.findMany({
      where: { userId },
      orderBy: { createdAt: "desc" },
      select: sessionSelect,
    });
  }

  findSessionById(userId: string, sessionId: string) {
    return prisma.refreshToken.findFirst({
      where: { id: sessionId, userId },
      select: sessionSelect,
    });
  }

  deleteSessionById(userId: string, sessionId: string) {
    return prisma.refreshToken.deleteMany({
      where: { id: sessionId, userId },
    });
  }

  deleteAllSessionsByUserId(userId: string) {
    return prisma.refreshToken.deleteMany({
      where: { userId },
    });
  }

  // ────── Device Management ──────

  findDevicesByUserId(userId: string) {
    return prisma.userDevice.findMany({
      where: { userId },
      orderBy: { lastLoginAt: "desc" },
      select: deviceSelect,
    });
  }

  findDeviceById(userId: string, deviceId: string) {
    return prisma.userDevice.findFirst({
      where: { id: deviceId, userId },
      select: deviceSelect,
    });
  }

  deleteDeviceById(userId: string, deviceId: string) {
    return prisma.userDevice.deleteMany({
      where: { id: deviceId, userId },
    });
  }

  /**
   * Lấy toàn bộ danh sách avatarUrl hiện tại của các User đang lưu trong DB
   */
  async getAllUserAvatarUrls(): Promise<string[]> {
    const users = await this.db.user.findMany({
      where: {
        avatarUrl: { not: null },
      },
      select: {
        avatarUrl: true,
      },
    });

    return users
      .map((u) => u.avatarUrl)
      .filter((url): url is string => Boolean(url));
  }

  /**
   * Lấy danh sách email của tất cả người dùng có quyền Quản trị (vai trò ADMIN / SUPER_ADMIN)
   */
  async findAdminUsers(): Promise<
    Array<{ id: string; email: string; fullName: string | null }>
  > {
    const admins = await prisma.user.findMany({
      where: {
        isActive: true,
        deletedAt: null,
        email: { not: null },
        OR: [
          { role: { name: ROLES.ADMIN } },
          {
            role: {
              permissions: {
                some: {
                  permission: {
                    name: {
                      in: [
                        PERMISSIONS.USER_ROLE_ASSIGN,
                        PERMISSIONS.ROLE_PERMISSION_ASSIGN,
                        PERMISSIONS.AUDIT_LOG_READ,
                        PERMISSIONS.CRON_JOB_READ,
                      ],
                    },
                  },
                },
              },
            },
          },
        ],
      },
      select: {
        id: true,
        email: true,
        fullName: true,
      },
    });

    return admins as Array<{
      id: string;
      email: string;
      fullName: string | null;
    }>;
  }

  /**
   * Truy vấn danh sách người dùng đang hoạt động có thẩm quyền nhận cảnh báo vi phạm PPE
   * cho một công trường (dùng cho M2M nội bộ từ Notification Service).
   */
  async findIncidentNotificationRecipients(siteId?: string): Promise<
    Array<{
      id: string;
      email: string | null;
      fullName: string | null;
      role: string | null;
    }>
  > {
    const incidentHandlerRoleFilter = {
      OR: [
        {
          role: {
            name: {
              in: [
                ROLES.SAFETY_MANAGER,
                ROLES.SAFETY_OFFICER,
                ROLES.MANAGER,
              ],
            },
          },
        },
        {
          role: {
            permissions: {
              some: {
                permission: {
                  name: {
                    in: [
                      PERMISSIONS.PPE_INCIDENT_REVIEW,
                      PERMISSIONS.PPE_INCIDENT_MANAGE,
                      PERMISSIONS.PPE_INCIDENT_UPDATE,
                      PERMISSIONS.PPE_INCIDENT_READ,
                    ],
                  },
                },
              },
            },
          },
        },
      ],
    };

    const scopeFilter = siteId
      ? {
          OR: [
            { role: { name: ROLES.ADMIN } },
            {
              AND: [
                incidentHandlerRoleFilter,
                { siteIds: { has: siteId } },
              ],
            },
          ],
        }
      : {
          role: { name: ROLES.ADMIN },
        };

    const users = await this.db.user.findMany({
      where: {
        isActive: true,
        deletedAt: null,
        ...scopeFilter,
      },
      select: {
        id: true,
        email: true,
        fullName: true,
        role: {
          select: {
            name: true,
          },
        },
      },
    });

    return users.map((u) => ({
      id: u.id,
      email: u.email,
      fullName: u.fullName,
      role: u.role?.name || null,
    }));
  }

  // ────── Audit Log ──────

  createAuditLog(data: {
    actorId?: string;
    action: string;
    targetType: string;
    targetId?: string;
    details?: Record<string, unknown> | null;
    ipAddress?: string;
    userAgent?: string;
  }) {
    return prisma.auditLog.create({
      data: {
        actorId: data.actorId,
        action: data.action,
        targetType: data.targetType,
        targetId: data.targetId ?? SYSTEM_TARGET_ID, // AuditLog.targetId is required String in schema
        details: (data.details ?? undefined) as
          Prisma.InputJsonValue | undefined,
        ipAddress: data.ipAddress,
        userAgent: data.userAgent,
      },
    });
  }
}

export const userRepository = new UserRepository();
