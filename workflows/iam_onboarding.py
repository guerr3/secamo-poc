import string
from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy


def _generate_legacy_temp_password(length: int = 16) -> str:
    """Deterministic fallback for replaying pre-patch workflow histories."""

    seeded_random = workflow.new_random()
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = [
        seeded_random.choice(string.ascii_uppercase),
        seeded_random.choice(string.ascii_lowercase),
        seeded_random.choice(string.digits),
        seeded_random.choice("!@#$%^&*"),
    ]
    password += [seeded_random.choice(alphabet) for _ in range(max(length - len(password), 0))]
    shuffled = list(password)
    seeded_random.shuffle(shuffled)
    return "".join(shuffled)


with workflow.unsafe.imports_passed_through():
    from activities.audit import create_audit_log
    from activities.hitl import request_hitl_approval
    from activities.identity import (
        identity_assign_license,
        identity_create_user,
        identity_generate_temp_password,
        identity_get_user,
        identity_reset_password,
        identity_revoke_sessions,
        identity_update_user,
    )
    from shared.models import (
        ApprovalDecision,
        HiTLRequest,
        IdentityUser,
        LifecycleAction,
        TenantConfig,
        UserLifecycleCaseInput,
    )
    from shared.workflow_helpers import bootstrap_tenant

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
    WF-01 - User lifecycle management workflow.
    Task Queue: user-lifecycle
    Actions: create | update | delete | password_reset
    """

    def __init__(self) -> None:
        self._approval: ApprovalDecision | None = None

    @workflow.signal
    async def approve(self, decision: ApprovalDecision) -> None:
        self._approval = decision

    @workflow.run
    async def run(self, case: UserLifecycleCaseInput) -> str:
        action = LifecycleAction(case.action)
        user_email = case.user_email

        workflow.logger.info(
            "WF-01 started - tenant=%s action=%s user=%s",
            case.tenant_id,
            action.value,
            user_email,
        )

        config: TenantConfig = await bootstrap_tenant(
            tenant_id=case.tenant_id,
            retry_policy=RETRY_POLICY,
            timeout=TIMEOUT,
        )
        runtime_retry = RetryPolicy(maximum_attempts=config.max_activity_attempts)

        # Idempotency guard: check whether the user already exists.
        existing_user: IdentityUser | None = await workflow.execute_activity(
            identity_get_user,
            args=[case.tenant_id, user_email],
            start_to_close_timeout=TIMEOUT,
            retry_policy=runtime_retry,
        )

        result_msg = ""

        if action == LifecycleAction.CREATE:
            if existing_user:
                result_msg = (
                    f"User '{user_email}' already exists "
                    f"(id={existing_user.user_id}). Skipped."
                )
            else:
                create_user_data = dict(case.user_data)
                create_user_data.setdefault("email", user_email)
                create_user_data.setdefault("user_id", case.user_id)
                if config.display_name:
                    create_user_data.setdefault("company_name", config.display_name)

                new_user: IdentityUser = await workflow.execute_activity(
                    identity_create_user,
                    args=[
                        case.tenant_id,
                        create_user_data,
                    ],
                    start_to_close_timeout=TIMEOUT,
                    retry_policy=runtime_retry,
                )

                # UserLifecycleCaseInput intentionally does not carry profile/license attributes.
                license_msg = ""
                license_sku = ""

                if license_sku:
                    approval_request = _build_license_approval_request(
                        tenant_id=case.tenant_id,
                        workflow_id=workflow.info().workflow_id,
                        user_id=new_user.user_id,
                        user_email=new_user.email,
                        license_sku=license_sku,
                        reviewer_email=config.soc_analyst_email or case.requester,
                        timeout_hours=config.hitl_timeout_hours,
                    )

                    if workflow.patched("wf01-inline-license-hitl-v1"):
                        self._approval = None
                        approval_request = approval_request.model_copy(
                            update={
                                "run_id": workflow.info().run_id,
                            }
                        )
                        await workflow.execute_activity(
                            request_hitl_approval,
                            args=[case.tenant_id, approval_request],
                            start_to_close_timeout=TIMEOUT,
                            retry_policy=runtime_retry,
                        )
                        try:
                            await workflow.wait_condition(
                                lambda: self._approval is not None,
                                timeout=timedelta(hours=config.hitl_timeout_hours),
                            )
                            decision = self._approval
                        except TimeoutError:
                            decision = None

                    if decision and decision.approved and decision.action == LICENSE_APPROVE_ACTION:
                        await workflow.execute_activity(
                            identity_assign_license,
                            args=[
                                case.tenant_id,
                                new_user.user_id,
                                license_sku,
                            ],
                            start_to_close_timeout=TIMEOUT,
                            retry_policy=runtime_retry,
                        )
                        license_msg = f" License '{license_sku}' approved and assigned."
                    elif decision is None:
                        license_msg = f" License assignment for '{license_sku}' is pending (timeout)."
                    else:
                        license_msg = f" License assignment for '{license_sku}' was rejected."

                result_msg = (
                    f"User '{new_user.email}' created (id={new_user.user_id})."
                    f"{license_msg}"
                )

        elif action == LifecycleAction.UPDATE:
            if not existing_user:
                raise ValueError(f"User '{user_email}' not found for update.")
            updates = dict(case.user_data.get("updates", case.user_data))
            updates.pop("user_id", None)
            updates.pop("email", None)
            updates.pop("user_email", None)
            if not updates:
                result_msg = f"User '{existing_user.email}' update skipped (no fields provided)."
            else:
                await workflow.execute_activity(
                    identity_update_user,
                    args=[
                        case.tenant_id,
                        existing_user.user_id,
                        updates,
                    ],
                    start_to_close_timeout=TIMEOUT,
                    retry_policy=runtime_retry,
                )
                result_msg = f"User '{existing_user.email}' updated."

        elif action == LifecycleAction.DELETE:
            if not existing_user:
                raise ValueError(f"User '{user_email}' not found for delete.")
            await workflow.execute_activity(
                identity_revoke_sessions,
                args=[case.tenant_id, existing_user.user_id],
                start_to_close_timeout=TIMEOUT,
                retry_policy=runtime_retry,
            )
            await workflow.execute_activity(
                identity_update_user,
                args=[
                    case.tenant_id,
                    existing_user.user_id,
                    {"accountEnabled": False},
                ],
                start_to_close_timeout=TIMEOUT,
                retry_policy=runtime_retry,
            )
            result_msg = f"User '{existing_user.email}' disabled."

        elif action == LifecycleAction.PASSWORD_RESET:
            if not existing_user:
                raise ValueError(f"User '{user_email}' not found for password reset.")

            if workflow.patched("wf01-password-generation-activity-v1"):
                temp_password = await workflow.execute_activity(
                    identity_generate_temp_password,
                    args=[16],
                    start_to_close_timeout=TIMEOUT,
                    retry_policy=runtime_retry,
                )
            else:
                temp_password = _generate_legacy_temp_password()

            await workflow.execute_activity(
                identity_reset_password,
                args=[
                    case.tenant_id,
                    existing_user.user_id,
                    temp_password,
                ],
                start_to_close_timeout=TIMEOUT,
                retry_policy=runtime_retry,
            )
            result_msg = f"Password reset for '{existing_user.email}'."

        await workflow.execute_activity(
            create_audit_log,
            args=[
                case.tenant_id,
                workflow.info().workflow_id,
                action.value,
                result_msg,
                {
                    "requester": case.requester,
                    "ticket_id": "",
                },
            ],
            start_to_close_timeout=TIMEOUT,
            retry_policy=runtime_retry,
        )

        workflow.logger.info("WF-01 completed - %s", result_msg)
        return result_msg
