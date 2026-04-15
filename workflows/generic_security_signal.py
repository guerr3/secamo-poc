from temporalio import workflow

with workflow.unsafe.imports_passed_through():
    from shared.models.canonical import DefenderSecuritySignalEvent, Envelope


@workflow.defn
class GenericSecuritySignalWorkflow:
    """WF-GEN — Generic handler for non-alert Defender security signals."""

    @workflow.run
    async def run(self, event: Envelope) -> str:
        if not isinstance(event.payload, DefenderSecuritySignalEvent):
            raise ValueError("WF-GEN requires defender.security_signal payload in Envelope input")

        payload = event.payload
        workflow.logger.info(
            "WF-GEN processed security signal tenant=%s signal=%s resource_type=%s provider_event_type=%s",
            event.tenant_id,
            payload.signal_id,
            payload.resource_type,
            payload.provider_event_type,
        )
        return "processed"
