import secrets
import string
from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy


def _generate_temp_password(length: int = 16) -> str:
    """Generate a cryptographically random temporary password."""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    # Guarantee at least one of each required class
    password = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%^&*"),
    ]
    password += [secrets.choice(alphabet) for _ in range(length - len(password))]
    # Shuffle to avoid predictable prefix
    shuffled = list(password)
    secrets_module = secrets.SystemRandom()
    secrets_module.shuffle(shuffled)
    return "".join(shuffled)



with workflow.unsafe.imports_passed_through():
    from shared.config import QUEUE_INTERACTIONS, QUEUE_POLLING, QUEUE_USER_LIFECYCLE, SECAMO_SENDER_EMAIL
    from shared.models import (
        HiTLApprovalRequest,
        HiTLRequest,
        IdentityUser,
        LifecycleAction,
        PollingManagerInput,
        TenantConfig,
        UserDeprovisioningRequest,
    )
    from shared.models.canonical import Envelope, IamOnboardingEvent
    from shared.workflow_helpers import bootstrap_tenant, start_child_workflow_idempotent
    from activities.identity import (
        identity_assign_license,
        identity_create_user,
        identity_get_user,
        identity_reset_password,
        identity_update_user,
    )
    from activities.audit import create_audit_log
    from workflows.child.hitl_approval import HiTLApprovalWorkflow
    from workflows.polling_manager import PollingManagerWorkflow
    from workflows.child.user_deprovisioning import UserDeprovisioningWorkflow

# ── Module-level constants ────────────────────────────────────
RETRY_POLICY = RetryPolicy(maximum_attempts=3)
TIMEOUT = timedelta(seconds=30)
LICENSE_APPROVE_ACTION = "approve_license"
LICENSE_REJECT_ACTION = "dismiss"


def _build_license_approval_request(
    *,
    tenant_id: str,
    workflow_id: str,
    user_id: str,
    user_email: str,
    license_sku: str,
    reviewer_email: str,
    timeout_hours: int,
) -> HiTLRequest:
    return HiTLRequest(
        workflow_id=workflow_id,
        run_id="",
        tenant_id=tenant_id,
        title=f"License approval required for {user_email}",
        description=(
            f"Approve or reject license allocation for user {user_email}. "
            f"Requested license SKU: {license_sku}."
        ),
        allowed_actions=[LICENSE_APPROVE_ACTION, LICENSE_REJECT_ACTION],
        reviewer_email=reviewer_email,
        channels=["email"],
        timeout_hours=timeout_hours,
        metadata={
            "workflow": "WF-01",
            "stage": "license_approval",
            "user_id": user_id,
            "user_email": user_email,
            "license_sku": license_sku,
        },
    )


@workflow.defn
class IamOnboardingWorkflow:
    """
    WF-01 — User Lifecycle Management (IAM provider-agnostic identity CRUD).
    Task Queue: user-lifecycle
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

        config: TenantConfig = await bootstrap_tenant(
            tenant_id=event.tenant_id,
            retry_policy=RETRY_POLICY,
            timeout=TIMEOUT,
        )
        runtime_retry = RetryPolicy(maximum_attempts=config.max_activity_attempts)

        for provider_cfg in config.polling_providers:
            polling_workflow_id = (
                f"polling-{event.tenant_id}-{provider_cfg.provider}-{provider_cfg.resource_type}"
            )
            await start_child_workflow_idempotent(
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
                workflow_id=polling_workflow_id,
                task_queue=QUEUE_POLLING,
                parent_close_policy=workflow.ParentClosePolicy.ABANDON,
            )

        # 3. Idempotency check — kijk of gebruiker al bestaat
        existing_user: IdentityUser | None = await workflow.execute_activity(
            identity_get_user,
            args=[event.tenant_id, user_email],
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
                new_user: IdentityUser = await workflow.execute_activity(
                    identity_create_user,
                    args=[event.tenant_id, user_data],
                    start_to_close_timeout=TIMEOUT,
                    retry_policy=runtime_retry,
                )

                license_msg = ""
                license_sku = str(user_data.get("license_sku") or "").strip()

                if license_sku:
                    approval_request = _build_license_approval_request(
                        tenant_id=event.tenant_id,
                        workflow_id=workflow.info().workflow_id,
                        user_id=new_user.user_id,
                        user_email=new_user.email,
                        license_sku=license_sku,
                        reviewer_email=SECAMO_SENDER_EMAIL,
                        timeout_hours=config.hitl_timeout_hours,
                    )

                    decision = await workflow.execute_child_workflow(
                        HiTLApprovalWorkflow.run,
                        HiTLApprovalRequest(
                            tenant_id=event.tenant_id,
                            hitl_request=approval_request,
                            hitl_timeout_hours=config.hitl_timeout_hours,
                            auto_isolate_on_timeout=False,
                            escalation_enabled=False,
                            edr_provider=config.edr_provider,
                            ticketing_provider=config.ticketing_provider,
                            device_id=None,
                        ),
                        id=f"{workflow.info().workflow_id}-license-approval",
                        task_queue=QUEUE_INTERACTIONS,
                    )

                    if decision and decision.approved and decision.action == LICENSE_APPROVE_ACTION:
                        await workflow.execute_activity(
                            identity_assign_license,
                            args=[
                                event.tenant_id,
                                new_user.user_id,
                                license_sku,
                            ],
                            start_to_close_timeout=TIMEOUT,
                            retry_policy=runtime_retry,
                        )
                        license_msg = (
                            f" Licentie '{license_sku}' goedgekeurd en toegekend."
                        )
                    elif decision is None:
                        license_msg = (
                            f" Licentietoekenning voor '{license_sku}' in afwachting (timeout)."
                        )
                    else:
                        license_msg = (
                            f" Licentietoekenning voor '{license_sku}' afgewezen."
                        )

                result_msg = (
                    f"Gebruiker '{new_user.email}' aangemaakt (id={new_user.user_id})."
                    f"{license_msg}"
                )

        elif action == LifecycleAction.UPDATE:
            if not existing_user:
                raise ValueError(
                    f"Gebruiker '{user_email}' niet gevonden voor update."
                )
            await workflow.execute_activity(
                identity_update_user,
                args=[
                    event.tenant_id,
                    existing_user.user_id,
                    {
                        "department": user_data.get("department", ""),
                        "jobTitle": user_data.get("role", ""),
                    },
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
                ),
                id=f"{workflow.info().workflow_id}-deprovision",
                task_queue=QUEUE_USER_LIFECYCLE,
            )
            result_msg = f"Gebruiker '{existing_user.email}' uitgeschakeld."

        elif action == LifecycleAction.PASSWORD_RESET:
            if not existing_user:
                raise ValueError(
                    f"Gebruiker '{user_email}' niet gevonden voor password reset."
                )
            await workflow.execute_activity(
                identity_reset_password,
                args=[
                    event.tenant_id,
                    existing_user.user_id,
                    _generate_temp_password(),
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
