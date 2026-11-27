import { eventBus, EventBusService } from "../services/event-bus.service";
import { EVENT_NAMES } from "../constants/event.constant";
import { WEBHOOK_EVENTS } from "../constants/integration.constant";
import {
  integrationService,
  IntegrationService,
} from "../../modules/integration/integration.service";
import {
  EventEnvelope,
  PPEIncidentCreatedPayload,
  PPEIncidentAssignedPayload,
  PPEIncidentResolvedPayload,
} from "../types/event.type";

export class WebhookSubscriber {
  private readonly bus: EventBusService;
  private readonly integration: Pick<
    IntegrationService,
    "dispatchDomainWebhookEvent"
  >;

  constructor(
    bus: EventBusService = eventBus,
    integration: Pick<
      IntegrationService,
      "dispatchDomainWebhookEvent"
    > = integrationService,
  ) {
    this.bus = bus;
    this.integration = integration;
  }

  public register(): void {
    this.bus.subscribe(
      EVENT_NAMES.PPE_INCIDENT_CREATED,
      async (envelope: EventEnvelope<PPEIncidentCreatedPayload>) => {
        try {
          await this.integration.dispatchDomainWebhookEvent(
            WEBHOOK_EVENTS.PPE_INCIDENT_CREATED,
            {
              eventId: envelope.id,
              event: WEBHOOK_EVENTS.PPE_INCIDENT_CREATED,
              timestamp: envelope.timestamp,
              traceId: envelope.traceId ?? null,
              source: envelope.source,
              data: envelope.payload as unknown as Record<string, unknown>,
            },
            { scope: "broadcast" },
          );
        } catch (err: any) {
          console.warn(
            "[WebhookSubscriber] Failed to dispatch ppe.incident.created webhook:",
            err?.message || err,
          );
        }
      },
    );

    this.bus.subscribe(
      EVENT_NAMES.PPE_INCIDENT_ASSIGNED,
      async (envelope: EventEnvelope<PPEIncidentAssignedPayload>) => {
        try {
          await this.integration.dispatchDomainWebhookEvent(
            WEBHOOK_EVENTS.PPE_INCIDENT_ASSIGNED,
            {
              eventId: envelope.id,
              event: WEBHOOK_EVENTS.PPE_INCIDENT_ASSIGNED,
              timestamp: envelope.timestamp,
              traceId: envelope.traceId ?? null,
              source: envelope.source,
              data: envelope.payload as unknown as Record<string, unknown>,
            },
            { scope: "broadcast" },
          );
        } catch (err: any) {
          console.warn(
            "[WebhookSubscriber] Failed to dispatch ppe.incident.assigned webhook:",
            err?.message || err,
          );
        }
      },
    );

    this.bus.subscribe(
      EVENT_NAMES.PPE_INCIDENT_RESOLVED,
      async (envelope: EventEnvelope<PPEIncidentResolvedPayload>) => {
        try {
          await this.integration.dispatchDomainWebhookEvent(
            WEBHOOK_EVENTS.PPE_INCIDENT_RESOLVED,
            {
              eventId: envelope.id,
              event: WEBHOOK_EVENTS.PPE_INCIDENT_RESOLVED,
              timestamp: envelope.timestamp,
              traceId: envelope.traceId ?? null,
              source: envelope.source,
              data: envelope.payload as unknown as Record<string, unknown>,
            },
            { scope: "broadcast" },
          );
        } catch (err: any) {
          console.warn(
            "[WebhookSubscriber] Failed to dispatch ppe.incident.resolved webhook:",
            err?.message || err,
          );
        }
      },
    );
  }
}

export const webhookSubscriber = new WebhookSubscriber();
