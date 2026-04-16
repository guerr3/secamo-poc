from pathlib import Path


def test_ingress_terraform_exposes_graph_notification_get_validation_route() -> None:
    source = Path("terraform/modules/ingress/main.tf").read_text(encoding="utf-8")

    assert 'resource "aws_api_gateway_method" "graph_notifications_tenant_get"' in source
    assert 'http_method   = "GET"' in source
    assert 'authorization = "NONE"' in source
    assert 'resource "aws_api_gateway_integration" "graph_notifications_tenant_get"' in source


def test_ingress_terraform_graph_notification_get_is_in_deployment_triggers() -> None:
    source = Path("terraform/modules/ingress/main.tf").read_text(encoding="utf-8")

    assert "aws_api_gateway_method.graph_notifications_tenant_get.id" in source
    assert "aws_api_gateway_integration.graph_notifications_tenant_get.id" in source
