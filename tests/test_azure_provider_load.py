"""The Azure provider module must import and its debug fetch must run.

Regression test for the April 2026 truncation of
cloudctl/providers/azure/provider.py, which left the file cut off mid-line so
`import cloudctl.providers.azure.provider` raised SyntaxError and every Azure
command (and Azure debug context) failed. No Azure SDK or credentials needed:
the SDK clients are replaced with mocks.
"""
from __future__ import annotations

import ast
import importlib
import inspect
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import cloudctl.providers.azure.provider as azure_mod
from cloudctl.providers.base import CloudProvider

_SRC = Path(azure_mod.__file__)


def test_azure_provider_source_parses():
    ast.parse(_SRC.read_text(encoding="utf-8"))


def test_azure_provider_module_imports():
    mod = importlib.reload(azure_mod)
    assert issubclass(mod.AzureProvider, CloudProvider)


def test_fetch_debug_context_defined_once():
    tree = ast.parse(_SRC.read_text(encoding="utf-8"))
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "AzureProvider")
    names = [n.name for n in cls.body if isinstance(n, ast.FunctionDef)]
    dupes = {n for n in names if names.count(n) > 1}
    assert not dupes, f"methods defined more than once: {sorted(dupes)}"


def test_azure_provider_implements_every_abstract_method():
    assert not inspect.isabstract(azure_mod.AzureProvider)


@pytest.fixture
def provider(monkeypatch):
    monkeypatch.setattr(azure_mod, "_AZURE_AVAILABLE", True)
    monkeypatch.setattr(azure_mod, "DefaultAzureCredential", MagicMock(), raising=False)
    return azure_mod.AzureProvider(subscription_id="00000000-0000-0000-0000-000000000000")


def _activity_event(op: str, rid: str) -> SimpleNamespace:
    return SimpleNamespace(
        operation_name=SimpleNamespace(value=op),
        resource_id=rid,
        event_timestamp=datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc),
        status=SimpleNamespace(value="Succeeded"),
        caller="someone@example.com",
    )


def test_fetch_debug_context_collects_activity_log(provider, monkeypatch):
    client = MagicMock()
    client.activity_logs.list.return_value = [
        _activity_event("Microsoft.Web/sites/write", "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Web/sites/orders-api"),
        _activity_event("Microsoft.Web/sites/read", "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Web/sites/orders-api"),
        _activity_event("Microsoft.Storage/storageAccounts/write", "/subscriptions/x/other"),
    ]
    client.diagnostic_settings.list_at_subscription_level.return_value = []
    monkeypatch.setattr(azure_mod, "_MONITOR_AVAILABLE", True)
    monkeypatch.setattr(azure_mod, "MonitorManagementClient", MagicMock(return_value=client), raising=False)

    context: dict = {}
    provider.fetch_debug_context("orders api 500s", ["orders-api"], context, minutes=60)

    events = context.get("audit_logs")
    assert events and len(events) == 1
    assert events[0]["source"] == "AzureActivityLog"
    assert events[0]["event"] == "microsoft.web/sites/write"


def test_fetch_debug_context_without_monitor_sdk_is_a_no_op(provider, monkeypatch):
    monkeypatch.setattr(azure_mod, "_MONITOR_AVAILABLE", False)
    context: dict = {}
    provider.fetch_debug_context("anything", ["svc"], context)
    assert "audit_logs" not in context
    assert "azure_monitor_logs" not in context
