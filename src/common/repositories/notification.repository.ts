import { prisma } from "../../database/prisma.client";
import {
  NOTIFICATION_STATUS,
  NOTIFICATION_TYPE,
  NOTIFICATION_PRIORITY,
  EMAIL_STATUS,
} from "../constants/notification.constant";

export interface ClaimedEmailRecord {
  id: string;
  userId: string | null;
  toEmail: string;
  subject: string;
  templateKey: string;
  templateData: unknown;
  status: string;
  attempts: number;
  lastError: string | null;
  sentAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export class NotificationRepository {
  private readonly db = prisma;

  async findTemplateByCode(code: string) {
    const t = await this.db.notificationTemplate.findUnique({
      where: { code },
    });
    if (!t) return null;
    return {
      id: t.id,
      code: t.code,
      name: t.name,
      channel: "EMAIL",
      subjectTemplate: t.subject || t.title || t.name,
      contentTemplate: t.content,
      status: t.isActive ? "ACTIVE" : "INACTIVE",
    };
  }

  async createSingleNotification(data: {
    userId: string;
    channel?: string;
    severity?: string;
    title: string;
    content: string;
    actionUrl?: string;
    metadata?: Record<string, unknown>;
  }) {
    return this.createWebNotification({
      userId: data.userId,
      title: data.title,
      content: data.content,
      priority: data.severity,
      actionUrl: data.actionUrl,
      metadata: data.metadata,
    });
  }

  async createWebNotification(data: {
    userId: string;
    type?: string;
    priority?: string;
    title: string;
    content: string;
    actionUrl?: string;
    metadata?: Record<string, unknown>;
  }) {
    return this.db.notification.create({
      data: {
        userId: data.userId,
        type: data.type || NOTIFICATION_TYPE.INFO,
        priority: data.priority || NOTIFICATION_PRIORITY.NORMAL,
        title: data.title,
        content: data.content,
        actionUrl: data.actionUrl,
        metadata: data.metadata as any,
        isRead: false,
      },
    });
  }

  async createEmailNotification(data: {
    userId?: string | null;
    toEmail: string;
    subject: string;
    templateKey: string;
    templateData: unknown;
  }) {
    return this.db.emailNotification.create({
      data: {
        userId: data.userId ?? null,
        toEmail: data.toEmail,
        subject: data.subject,
        templateKey: data.templateKey,
        templateData: data.templateData as any,
        status: EMAIL_STATUS.PENDING,
        attempts: 0,
      },
    });
  }

  async claimPendingEmails(batchSize = 20): Promise<ClaimedEmailRecord[]> {
    return this.db.$queryRaw<ClaimedEmailRecord[]>`
      UPDATE email_notifications
      SET status = ${EMAIL_STATUS.PROCESSING}, updated_at = NOW()
      WHERE id IN (
        SELECT id FROM email_notifications
        WHERE (
          status = ${EMAIL_STATUS.PENDING}
          OR (status = ${EMAIL_STATUS.PROCESSING} AND updated_at < NOW() - INTERVAL '15 minutes')
        )
        AND attempts < 5
        ORDER BY created_at ASC
        LIMIT ${batchSize}
        FOR UPDATE SKIP LOCKED
      )
      RETURNING
        id,
        user_id AS "userId",
        to_email AS "toEmail",
        subject,
        template_key AS "templateKey",
        template_data AS "templateData",
        status,
        attempts,
        last_error AS "lastError",
        sent_at AS "sentAt",
        created_at AS "createdAt",
        updated_at AS "updatedAt"
    `;
  }

  async updateEmailStatus(
    id: string,
    data: {
      status: string;
      attempts?: number;
      lastError?: string | null;
      sentAt?: Date | null;
    },
  ) {
    return this.db.emailNotification.update({
      where: { id },
      data: {
        status: data.status,
        ...(data.attempts !== undefined && { attempts: data.attempts }),
        ...(data.lastError !== undefined && { lastError: data.lastError }),
        ...(data.sentAt !== undefined && { sentAt: data.sentAt }),
      },
    });
  }

  async resetEmailForRetry(id: string) {
    return this.db.emailNotification.update({
      where: { id },
      data: {
        status: EMAIL_STATUS.PENDING,
        attempts: 0,
        lastError: null,
      },
    });
  }
}

export const notificationRepository = new NotificationRepository();
