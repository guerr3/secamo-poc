from pathlib import Path


def test_onboarding_subscription_reconcile_is_best_effort() -> None:
    source = Path("workflows/child/onboarding_subscription_reconcile_stage.py").read_text(encoding="utf-8")

    assert "MissingGraphNotificationUrl" not in source
    assert "failed to create subscription" in source
    assert "skipping subscription create" in source
