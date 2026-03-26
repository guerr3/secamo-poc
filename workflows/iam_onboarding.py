from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy



with workflow.unsafe.imports_passed_through():
    from temporalio.exceptions import WorkflowAlreadyStartedError

    from shared.models import (
        GraphUser,
        LifecycleAction,
        PollingManagerInput,
        TenantConfig,
        TenantSecrets,
        UserDeprovisioningRequest,
    )
    from shared.models.canonical import Envelope, IamOnboardingEvent
    from shared.workflow_helpers import bootstrap_tenant
    from activities.graph_users import (
        graph_get_user,
        graph_create_user,
        graph_update_user,
        graph_assign_license,
        graph_reset_password,
    )
    from activities.audit import create_audit_log
    from workflows.polling_manager import PollingManagerWorkflow
    from workflows.child.user_deprovisioning import UserDeprovisioningWorkflow

# ── Module-level constants ────────────────────────────────────
RETRY_POLICY = RetryPolicy(maximum_attempts=3)
TIMEOUT = timedelta(seconds=30)


@workflow.defn
class IamOnboardingWorkflow:
    """
    WF-01 — User Lifecycle Management (IAM / Entra ID CRUD via Graph API).
    Task Queue: iam-graph
    Actions: create | update | delete | password_reset
    """

    @workflow.run
    async def run(self, event: Envelope) -> str:
        if not isinstance(event.payload, IamOnboardingEvent):
            raise ValueError("WF-01 requires iam.onboarding payload in Envelope input")

        payload = event.payload
        user_data = payload.user_data
        if not user_data or not user_data.get("email"):
            raise ValueError("WF-01 requires payload.user_data.email")

        action = LifecycleAction(payload.action)
        user_email = str(user_data["email"])

        workflow.logger.info(
            f"WF-01 gestart — tenant={event.tenant_id}, "
            f"action={action.value}, user={user_email}"
        )

        config: TenantConfig
        secrets: TenantSecrets
        config, secrets = await bootstrap_tenant(
            tenant_id=event.tenant_id,
            retry_policy=RETRY_POLICY,
            timeout=TIMEOUT,
            secret_type="graph",
        )
        runtime_retry = RetryPolicy(maximum_attempts=config.max_activity_attempts)

        for provider_cfg in config.polling_providers:
            polling_workflow_id = (
                f"polling-{event.tenant_id}-{provider_cfg.provider}-{provider_cfg.resource_type}"
            )
            try:
                await workflow.start_child_workflow(
                    PollingManagerWorkflow.run,
                    PollingManagerInput(
                        tenant_id=event.tenant_id,
                        provider=provider_cfg.provider,
                        resource_type=provider_cfg.resource_type,
                        secret_type=provider_cfg.secret_type,
                        poll_interval_seconds=provider_cfg.poll_interval_seconds,
                        cursor=None,
                        iteration=0,
                    ),
                    id=polling_workflow_id,
                    task_queue="poller",
                    parent_close_policy=workflow.ParentClosePolicy.ABANDON,
                )
            except WorkflowAlreadyStartedError:
                workflow.logger.info(
                    "Polling manager already running: %s",
                    polling_workflow_id,
                )

        # 3. Idempotency check — kijk of gebruiker al bestaat
        existing_user: GraphUser | None = await workflow.execute_activity(
            graph_get_user,
            args=[event.tenant_id, user_email, secrets],
            start_to_close_timeout=TIMEOUT,
            retry_policy=runtime_retry,
        )

        # 4. Actie-specifieke branch
        result_msg = ""

        if action == LifecycleAction.CREATE:
            if existing_user:
                result_msg = (
                    f"Gebruiker '{user_email}' bestaat al "
                    f"(id={existing_user.user_id}). Overgeslagen."
                )
            else:
                new_user: GraphUser = await workflow.execute_activity(
                    graph_create_user,
                    args=[event.tenant_id, user_data, secrets],
                    start_to_close_timeout=TIMEOUT,
                    retry_policy=runtime_retry,
                )

                # Optioneel: licentie toekennen
                if user_data.get("license_sku"):
                    await workflow.execute_activity(
                        graph_assign_license,
                        args=[
                            event.tenant_id,
                            new_user.user_id,
                            user_data["license_sku"],
                            secrets,
                        ],
                        start_to_close_timeout=TIMEOUT,
                        retry_policy=runtime_retry,
                    )

                result_msg = (
                    f"Gebruiker '{new_user.email}' aangemaakt (id={new_user.user_id})."
                )

        elif action == LifecycleAction.UPDATE:
            if not existing_user:
                raise ValueError(
                    f"Gebruiker '{user_email}' niet gevonden voor update."
                )
            await workflow.execute_activity(
                graph_update_user,
                args=[
                    event.tenant_id,
                    existing_user.user_id,
                    {
                        "department": user_data.get("department", ""),
                        "jobTitle": user_data.get("role", ""),
                    },
                    secrets,
                ],
                start_to_close_timeout=TIMEOUT,
                retry_policy=runtime_retry,
            )
            result_msg = f"Gebruiker '{existing_user.email}' bijgewerkt."

        elif action == LifecycleAction.DELETE:
            if not existing_user:
                raise ValueError(
                    f"Gebruiker '{user_email}' niet gevonden voor delete."
                )
            await workflow.execute_child_workflow(
                UserDeprovisioningWorkflow.run,
                UserDeprovisioningRequest(
                    tenant_id=event.tenant_id,
                    user_id=existing_user.user_id,
                    user_email=existing_user.email,
                    secrets=secrets,
                ),
                id=f"{workflow.info().workflow_id}-deprovision",
                task_queue="iam-graph",
            )
            result_msg = f"Gebruiker '{existing_user.email}' uitgeschakeld."

        elif action == LifecycleAction.PASSWORD_RESET:
            if not existing_user:
                raise ValueError(
                    f"Gebruiker '{user_email}' niet gevonden voor password reset."
                )
            await workflow.execute_activity(
                graph_reset_password,
                args=[
                    event.tenant_id,
                    existing_user.user_id,
                    "TempP@ss2025!",  # TODO: genereer veilig wachtwoord
                    secrets,
                ],
                start_to_close_timeout=TIMEOUT,
                retry_policy=runtime_retry,
            )
            result_msg = f"Wachtwoord gereset voor '{existing_user.email}'."

        # 5. Audit log
        await workflow.execute_activity(
            create_audit_log,
            args=[
                event.tenant_id,
                workflow.info().workflow_id,
                action.value,
                result_msg,
                {
                    "requester": str(event.metadata.get("requester") or "ingress-api"),
                    "ticket_id": str(event.metadata.get("ticket_id") or ""),
                },
            ],
            start_to_close_timeout=TIMEOUT,
            retry_policy=runtime_retry,
        )

        workflow.logger.info(f"WF-01 afgerond — {result_msg}")
        return result_msg
