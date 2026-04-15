from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ApplicationError

with workflow.unsafe.imports_passed_through():
    from activities.onboarding import provision_customer_secrets, register_customer_tenant
    from activities.tenant import get_tenant_config, get_tenant_secrets, validate_tenant_context
    from shared.models import OnboardingBootstrapStageRequest, OnboardingBootstrapStageResult, TenantConfig


RETRY_POLICY = RetryPolicy(maximum_attempts=3)
TIMEOUT = timedelta(seconds=30)


def _is_partial_onboarding_enabled(request: OnboardingBootstrapStageRequest) -> bool:
    raw = request.payload.config.get("allow_partial_onboarding") if isinstance(request.payload.config, dict) else None
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        return raw.strip().lower() in {"1", "true", "yes", "on"}
    return False


@workflow.defn
class OnboardingBootstrapStageWorkflow:
    """Provision tenant secrets/registration and resolve onboarding runtime config."""

    @workflow.run
    async def run(self, request: OnboardingBootstrapStageRequest) -> OnboardingBootstrapStageResult:
        if request.payload.tenant_id != request.tenant_id:
            raise ApplicationError(
                "Bootstrap stage requires payload.tenant_id to match request.tenant_id",
                type="TenantMismatch",
                non_retryable=True,
            )

        if not request.payload.welcome_email:
            raise ApplicationError(
                "customer.onboarding requires payload.welcome_email",
                type="MissingWelcomeEmail",
                non_retryable=True,
            )

        partial_onboarding = _is_partial_onboarding_enabled(request)

        provisioning_result: dict[str, str] = await workflow.execute_activity(
            provision_customer_secrets,
            args=[request.tenant_id, request.payload],
            start_to_close_timeout=TIMEOUT,
            retry_policy=RETRY_POLICY,
        )

        await workflow.execute_activity(
            register_customer_tenant,
            args=[request.tenant_id, request.payload],
            start_to_close_timeout=TIMEOUT,
            retry_policy=RETRY_POLICY,
        )

        await workflow.execute_activity(
            validate_tenant_context,
            args=[request.tenant_id],
            start_to_close_timeout=TIMEOUT,
            retry_policy=RETRY_POLICY,
        )

        config: TenantConfig = await workflow.execute_activity(
            get_tenant_config,
            args=[request.tenant_id],
            start_to_close_timeout=TIMEOUT,
            retry_policy=RETRY_POLICY,
        )
        runtime_retry = RetryPolicy(maximum_attempts=config.max_activity_attempts)

        await workflow.execute_activity(
            get_tenant_secrets,
            args=[request.tenant_id, "ticketing"],
            start_to_close_timeout=TIMEOUT,
            retry_policy=runtime_retry,
        )

        analyst_email = request.payload.soc_analyst_email or config.soc_analyst_email
        if not analyst_email:
            raise ApplicationError(
                "No SOC analyst email configured for onboarding confirmation",
                type="MissingSocAnalystEmail",
                non_retryable=True,
            )

        display_name = request.payload.display_name or config.display_name or request.tenant_id
        notification_url = str(provisioning_result.get("graph_notification_url") or "").strip()

        return OnboardingBootstrapStageResult(
            tenant_id=request.tenant_id,
            config=config,
            partial_onboarding=partial_onboarding,
            notification_url=notification_url,
            display_name=display_name,
            analyst_email=analyst_email,
            welcome_email=request.payload.welcome_email,
            requester=request.requester,
        )
