import { z } from "zod";
import { MAINTENANCE_STATUS } from "../../common/constants/maintenance.constant";
import { ROLES } from "../../common/constants/role.constant";
import { PERMISSIONS } from "../../common/constants/permission.constant";
import { isValidIpOrCidr } from "../../common/helpers/ip.helper";

const bypassIpItemSchema = z
  .string()
  .trim()
  .min(1, "IP address / subnet cannot be empty")
  .refine(isValidIpOrCidr, {
    message: "Invalid IPv4, IPv6, or CIDR format",
  });

const bypassRolesSchema = z
  .array(z.string().trim().min(1, "Role name cannot be empty"))
  .optional();

const bypassPermissionsSchema = z
  .array(z.string().trim().min(1, "Permission name cannot be empty"))
  .optional();

function hasAdminAccessAfterBothSpecified(data: {
  bypassRoles?: string[];
  bypassPermissions?: string[];
}): boolean {
  if (data.bypassRoles !== undefined && data.bypassPermissions !== undefined) {
    return (
      data.bypassRoles.includes(ROLES.ADMIN) ||
      data.bypassPermissions.includes(PERMISSIONS.MAINTENANCE_MANAGE)
    );
  }
  return true;
}

export const enableMaintenanceSchema = z
  .object({
    title: z
      .string()
      .trim()
      .min(1, "Title cannot be empty")
      .max(200, "Title is too long")
      .optional(),
    message: z
      .string()
      .trim()
      .min(1, "Message cannot be empty")
      .max(2000, "Message is too long")
      .optional(),
    startAt: z
      .string()
      .datetime({ message: "startAt must be a valid ISO 8601 datetime string" })
      .nullable()
      .optional(),
    estimatedEndAt: z
      .string()
      .datetime({
        message: "estimatedEndAt must be a valid ISO 8601 datetime string",
      })
      .nullable()
      .optional(),
    bypassPermissions: bypassPermissionsSchema,
    bypassRoles: bypassRolesSchema,
    bypassIps: z.array(bypassIpItemSchema).optional(),
    status: z
      .enum([MAINTENANCE_STATUS.MAINTENANCE, MAINTENANCE_STATUS.READ_ONLY])
      .optional(),
  })
  .refine(
    (data) => {
      if (data.startAt && data.estimatedEndAt) {
        return (
          new Date(data.startAt).getTime() <
          new Date(data.estimatedEndAt).getTime()
        );
      }
      return true;
    },
    {
      message: "estimatedEndAt must be after startAt",
      path: ["estimatedEndAt"],
    },
  )
  .refine(hasAdminAccessAfterBothSpecified, {
    message: `Anti-lockout guard: at least ${ROLES.ADMIN} in bypassRoles or ${PERMISSIONS.MAINTENANCE_MANAGE} in bypassPermissions must remain`,
    path: ["bypassRoles"],
  });

export const updateMaintenanceSchema = z
  .object({
    enabled: z.boolean().optional(),
    status: z
      .enum([
        MAINTENANCE_STATUS.ONLINE,
        MAINTENANCE_STATUS.MAINTENANCE,
        MAINTENANCE_STATUS.READ_ONLY,
      ])
      .optional(),
    title: z
      .string()
      .trim()
      .min(1, "Title cannot be empty")
      .max(200, "Title is too long")
      .optional(),
    message: z
      .string()
      .trim()
      .min(1, "Message cannot be empty")
      .max(2000, "Message is too long")
      .optional(),
    startAt: z
      .string()
      .datetime({ message: "startAt must be a valid ISO 8601 datetime string" })
      .nullable()
      .optional(),
    estimatedEndAt: z
      .string()
      .datetime({
        message: "estimatedEndAt must be a valid ISO 8601 datetime string",
      })
      .nullable()
      .optional(),
    bypassPermissions: bypassPermissionsSchema,
    bypassRoles: bypassRolesSchema,
    bypassIps: z.array(bypassIpItemSchema).optional(),
  })
  .refine(
    (data) => {
      if (data.startAt && data.estimatedEndAt) {
        return (
          new Date(data.startAt).getTime() <
          new Date(data.estimatedEndAt).getTime()
        );
      }
      return true;
    },
    {
      message: "estimatedEndAt must be after startAt",
      path: ["estimatedEndAt"],
    },
  )
  .refine(hasAdminAccessAfterBothSpecified, {
    message: `Anti-lockout guard: at least ${ROLES.ADMIN} in bypassRoles or ${PERMISSIONS.MAINTENANCE_MANAGE} in bypassPermissions must remain`,
    path: ["bypassRoles"],
  });
