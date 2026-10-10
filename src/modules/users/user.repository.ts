import { Prisma } from "@prisma/client";
import { prisma } from "../../database/prisma.client";
import { ROLES } from "../../common/constants/role.constant";
import { PERMISSIONS } from "../../common/constants/permission.constant";
import { SYSTEM_TARGET_ID } from "../../common/constants/audit-log.constant";
import { UserQueryDto } from "./user.dto";
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
  async findAll(query: UserQueryDto = {}) {
    const {
      search,
      email,
      fullName,
      roleName,
      isActive,
      isDeleted,
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
    if (roleName) {
      conditions.push({ role: { name: roleName } });
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

    const [data, total] = await prisma.$transaction([
      prisma.user.findMany({
        where,
        select: userSummarySelect,
        orderBy,
        skip,
        take,
      }),
      prisma.user.count({ where }),
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

    if (query.roleName) {
      whereConditions.push(Prisma.sql`r.name = ${query.roleName}`);
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

    const [rawUsers, countResult] = await prisma.$transaction([
      prisma.$queryRaw<
        Array<{
          id: string;
          email: string | null;
          full_name: string | null;
          avatar_url: string | null;
          phone_number: string | null;
          role_id: string;
          role_name: string;
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
          u.role_id, r.name as role_name, u.is_active, u.two_factor_enabled,
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
      prisma.$queryRaw<Array<{ count: bigint }>>`
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

  create(data: {
    email?: string;
    passwordHash?: string;
    fullName?: string;
    avatarUrl?: string;
    phoneNumber?: string;
    roleId: string;
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
    data: { isActive?: boolean; fullName?: string; phoneNumber?: string },
  ) {
    return prisma.user.update({
      where: { id },
      data,
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
   * Đếm số lượng người dùng đang hoạt động có đặc quyền quản trị hệ thống:
   * 1. Vai trò khớp với roleName (mặc định ROLES.ADMIN)
   * 2. Hoặc vai trò sở hữu các quyền quản trị then chốt (USER_ROLE_ASSIGN, ROLE_PERMISSION_ASSIGN)
   */
  async countActiveAdmins(roleName: string = ROLES.ADMIN): Promise<number> {
    return prisma.user.count({
      where: {
        deletedAt: null,
        isActive: true,
        OR: [
          { role: { name: roleName } },
          {
            role: {
              permissions: {
                some: {
                  permission: {
                    name: {
                      in: [
                        PERMISSIONS.USER_ROLE_ASSIGN,
                        PERMISSIONS.ROLE_PERMISSION_ASSIGN,
                      ],
                    },
                  },
                },
              },
            },
          },
        ],
      },
    });
  }

  async softDelete(id: string, adminId: string) {
    return prisma.$transaction([
      prisma.user.update({
        where: { id },
        data: {
          deletedAt: new Date(),
          deletedBy: adminId,
          isActive: false,
        },
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
    const users = await prisma.user.findMany({
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
