from __future__ import annotations

from temporalio import workflow

with workflow.unsafe.imports_passed_through():
    from temporalio.exceptions import WorkflowAlreadyStartedError

    from shared.models import AlertData, GraphNotificationEnvelope, RawIngressEnvelope, SecurityEvent
    from shared.models.mappers import resolve_webhook_route

@workflow.defn
class GraphIngressRouterWorkflow:
    """Route validated Microsoft Graph webhook notifications to child workflows."""

    @workflow.run
    async def run(self, envelope: RawIngressEnvelope) -> str:
        if not isinstance(envelope.raw_body, dict):
            workflow.logger.warning("Graph ingress envelope has non-object body, request_id=%s", envelope.request_id)
            return "ignored"

        payload = GraphNotificationEnvelope.model_validate(envelope.raw_body)
        if not payload.value:
            return "no-notifications"

        started = 0
        for item in payload.value:
            route = resolve_webhook_route(envelope.provider, item.resource)
            if route is None:
                workflow.logger.warning(
                    "No webhook route configured provider=%s resource=%s",
                    envelope.provider,
                    item.resource,
                )
                continue

            workflow_name, task_queue = route
            event = self._to_security_event(envelope=envelope, item=item)
            notification_key = event.event_id
            child_workflow_id = (
                f"graph-{envelope.tenant_id}-{item.subscriptionId}-{item.changeType}-{notification_key}"
            )

            try:
                await workflow.start_child_workflow(
                    workflow_name,
                    event,
                    id=child_workflow_id,
                    task_queue=task_queue,
                    parent_close_policy=workflow.ParentClosePolicy.ABANDON,
                )
                started += 1
            except WorkflowAlreadyStartedError:
                workflow.logger.info("Duplicate Graph notification skipped workflow_id=%s", child_workflow_id)

        return f"started={started}"

    def _to_security_event(self, envelope: RawIngressEnvelope, item) -> SecurityEvent:
        resource_data = item.resourceData or {}
        resource_id = str(resource_data.get("id") or item.resource.rsplit("/", 1)[-1] or item.subscriptionId)
        resource_normalized = item.resource.lower()

        event_type = "defender.alert"
        severity = str(resource_data.get("severity") or "medium").lower()
        alert = None
        if "alerts" in resource_normalized:
            alert = AlertData(
                alert_id=resource_id,
                severity=severity,
                title=str(resource_data.get("title") or "Graph alert"),
                description=str(resource_data.get("description") or "Graph webhook notification"),
                device_id=resource_data.get("deviceId") or resource_data.get("azureAdDeviceId"),
                user_email=resource_data.get("userPrincipalName") or resource_data.get("accountName"),
                source_ip=resource_data.get("ipAddress"),
                destination_ip=resource_data.get("destinationIp"),
            )
        elif "signin" in resource_normalized or "risky" in resource_normalized:
            event_type = "defender.impossible_travel"
            alert = AlertData(
                alert_id=resource_id,
                severity=severity,
                title=str(resource_data.get("riskEventType") or "Identity risk event"),
                description=str(resource_data.get("riskDetail") or "Graph identity notification"),
                user_email=resource_data.get("userPrincipalName"),
                source_ip=resource_data.get("ipAddress"),
                destination_ip=resource_data.get("ipAddress"),
            )

        return SecurityEvent(
            event_id=f"{item.subscriptionId}:{resource_id}:{item.changeType}",
            tenant_id=envelope.tenant_id,
            event_type=event_type,
            source_provider=envelope.provider,
            requester="graph-ingress",
            severity=severity,
            correlation_id=envelope.request_id,
            alert=alert,
            metadata={
                "subscription_id": item.subscriptionId,
                "resource": item.resource,
                "change_type": item.changeType,
                "subscription_expiration": item.subscriptionExpirationDateTime.isoformat()
                if item.subscriptionExpirationDateTime
                else None,
                "resource_data": resource_data,
            },
        )
