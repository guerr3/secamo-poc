from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

from shared.models import (
    LifecycleAction,
    LifecycleRequest,
    TenantConfig,
    TenantSecrets,
    GraphUser,
    UserDeprovisioningRequest,
)

with workflow.unsafe.imports_passed_through():
    from shared.workflow_helpers import bootstrap_tenant
    from activities.graph_users import (
        graph_get_user,
        graph_create_user,
        graph_update_user,
        graph_assign_license,
        graph_reset_password,
    )
    from activities.audit import create_audit_log
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
    async def run(self, request: LifecycleRequest) -> str:
        workflow.logger.info(
            f"WF-01 gestart — tenant={request.tenant_id}, "
            f"action={request.action.value}, user={request.user_data.email}"
        )

        config: TenantConfig
        secrets: TenantSecrets
        config, secrets = await bootstrap_tenant(
            tenant_id=request.tenant_id,
            retry_policy=RETRY_POLICY,
            timeout=TIMEOUT,
            secret_type="graph",
        )
        runtime_retry = RetryPolicy(maximum_attempts=config.max_activity_attempts)

        # 3. Idempotency check — kijk of gebruiker al bestaat
        existing_user: GraphUser | None = await workflow.execute_activity(
            graph_get_user,
            args=[request.tenant_id, request.user_data.email, secrets],
            start_to_close_timeout=TIMEOUT,
            retry_policy=runtime_retry,
        )

        # 4. Actie-specifieke branch
        result_msg = ""

        if request.action == LifecycleAction.CREATE:
            if existing_user:
                result_msg = (
                    f"Gebruiker '{request.user_data.email}' bestaat al "
                    f"(id={existing_user.user_id}). Overgeslagen."
                )
            else:
                new_user: GraphUser = await workflow.execute_activity(
                    graph_create_user,
                    args=[request.tenant_id, request.user_data, secrets],
                    start_to_close_timeout=TIMEOUT,
                    retry_policy=runtime_retry,
                )

                # Optioneel: licentie toekennen
                if request.user_data.license_sku:
                    await workflow.execute_activity(
                        graph_assign_license,
                        args=[
                            request.tenant_id,
                            new_user.user_id,
                            request.user_data.license_sku,
                            secrets,
                        ],
                        start_to_close_timeout=TIMEOUT,
                        retry_policy=runtime_retry,
                    )

                result_msg = (
                    f"Gebruiker '{new_user.email}' aangemaakt (id={new_user.user_id})."
                )

        elif request.action == LifecycleAction.UPDATE:
            if not existing_user:
                raise ValueError(
                    f"Gebruiker '{request.user_data.email}' niet gevonden voor update."
                )
            await workflow.execute_activity(
                graph_update_user,
                args=[
                    request.tenant_id,
                    existing_user.user_id,
                    {
                        "department": request.user_data.department,
                        "jobTitle": request.user_data.role,
                    },
                    secrets,
                ],
                start_to_close_timeout=TIMEOUT,
                retry_policy=runtime_retry,
            )
            result_msg = f"Gebruiker '{existing_user.email}' bijgewerkt."

        elif request.action == LifecycleAction.DELETE:
            if not existing_user:
                raise ValueError(
                    f"Gebruiker '{request.user_data.email}' niet gevonden voor delete."
                )
            await workflow.execute_child_workflow(
                UserDeprovisioningWorkflow.run,
                UserDeprovisioningRequest(
                    tenant_id=request.tenant_id,
                    user_id=existing_user.user_id,
                    user_email=existing_user.email,
                    secrets=secrets,
                ),
                id=f"{workflow.info().workflow_id}-deprovision",
                task_queue="iam-graph",
            )
            result_msg = f"Gebruiker '{existing_user.email}' uitgeschakeld."

        elif request.action == LifecycleAction.PASSWORD_RESET:
            if not existing_user:
                raise ValueError(
                    f"Gebruiker '{request.user_data.email}' niet gevonden voor password reset."
                )
            await workflow.execute_activity(
                graph_reset_password,
                args=[
                    request.tenant_id,
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
                request.tenant_id,
                workflow.info().workflow_id,
                request.action.value,
                result_msg,
                {"requester": request.requester, "ticket_id": request.ticket_id},
            ],
            start_to_close_timeout=TIMEOUT,
            retry_policy=runtime_retry,
        )

        workflow.logger.info(f"WF-01 afgerond — {result_msg}")
        return result_msg
