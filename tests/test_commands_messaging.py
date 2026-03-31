"""Tests for cloudctl.commands.messaging helper functions."""
from __future__ import annotations

from unittest.mock import patch

from cloudctl.commands.messaging import (
    _aws_queue_rows,
    _aws_stream_rows,
    _aws_topic_rows,
    _azure_queue_rows,
    _azure_stream_rows,
    _gcp_queue_rows,
    _gcp_stream_rows,
    _gcp_topic_rows,
)


_SQS = {"account": "prod", "name": "my-queue", "messages": 5, "region": "us-east-1"}
_SNS = {"account": "prod", "name": "my-topic", "region": "us-east-1"}
_EB  = {"account": "prod", "name": "default", "region": "us-east-1"}
_KIN = {"account": "prod", "name": "my-stream", "state": "ACTIVE", "region": "us-east-1"}
_MSK = {"account": "prod", "name": "my-cluster", "state": "ACTIVE", "region": "us-east-1"}
_SB  = {"account": "sub-1", "name": "my-ns", "sku": "Standard", "region": "eastus"}
_EH  = {"account": "sub-1", "name": "my-eh", "sku": "Standard", "state": "Active", "region": "eastus"}
_CT  = {"account": "proj-1", "name": "my-queue", "size": 10, "region": "us-central1"}
_PS  = {"account": "proj-1", "name": "my-topic"}
_PSS = {"account": "proj-1", "name": "my-sub", "topic": "my-topic"}


class TestAwsQueueRows:
    def test_returns_sqs_row(self, fake_cfg, mock_aws):
        mock_aws.list_sqs_queues.return_value = [_SQS]
        with patch("cloudctl.commands.messaging.get_aws_provider", return_value=mock_aws):
            rows = _aws_queue_rows(fake_cfg, None, None)
        assert rows[0]["Type"] == "SQS"
        assert rows[0]["Messages"] == 5

    def test_exception_skipped(self, fake_cfg, mock_aws):
        mock_aws.list_sqs_queues.side_effect = Exception("creds")
        with patch("cloudctl.commands.messaging.get_aws_provider", return_value=mock_aws):
            rows = _aws_queue_rows(fake_cfg, None, None)
        assert rows == []


class TestAzureQueueRows:
    def test_returns_servicebus_row(self, mock_azure):
        mock_azure.list_service_bus_namespaces.return_value = [_SB]
        with patch("cloudctl.commands.messaging.get_azure_provider", return_value=mock_azure):
            rows = _azure_queue_rows(None, None)
        assert "Service Bus" in rows[0]["Type"]

    def test_exception_returns_empty(self, mock_azure):
        mock_azure.list_service_bus_namespaces.side_effect = Exception("auth")
        with patch("cloudctl.commands.messaging.get_azure_provider", return_value=mock_azure):
            rows = _azure_queue_rows(None, None)
        assert rows == []


class TestGcpQueueRows:
    def test_returns_cloud_tasks_row(self, mock_gcp):
        mock_gcp.list_cloud_tasks.return_value = [_CT]
        with patch("cloudctl.commands.messaging.get_gcp_provider", return_value=mock_gcp):
            rows = _gcp_queue_rows(None, None)
        assert rows[0]["Type"] == "Cloud Tasks"

    def test_exception_returns_empty(self, mock_gcp):
        mock_gcp.list_cloud_tasks.side_effect = Exception("quota")
        with patch("cloudctl.commands.messaging.get_gcp_provider", return_value=mock_gcp):
            rows = _gcp_queue_rows(None, None)
        assert rows == []


class TestAwsTopicRows:
    def test_returns_sns_and_eventbridge(self, fake_cfg, mock_aws):
        mock_aws.list_sns_topics.return_value = [_SNS]
        mock_aws.list_eventbridge_buses.return_value = [_EB]
        with patch("cloudctl.commands.messaging.get_aws_provider", return_value=mock_aws):
            rows = _aws_topic_rows(fake_cfg, None, None)
        types = {r["Type"] for r in rows}
        assert "SNS" in types
        assert "EventBridge" in types

    def test_exception_skipped(self, fake_cfg, mock_aws):
        mock_aws.list_sns_topics.side_effect = Exception("creds")
        with patch("cloudctl.commands.messaging.get_aws_provider", return_value=mock_aws):
            rows = _aws_topic_rows(fake_cfg, None, None)
        assert rows == []


class TestGcpTopicRows:
    def test_returns_pubsub_row(self, mock_gcp):
        mock_gcp.list_pubsub_topics.return_value = [_PS]
        with patch("cloudctl.commands.messaging.get_gcp_provider", return_value=mock_gcp):
            rows = _gcp_topic_rows(None)
        assert rows[0]["Type"] == "Pub/Sub"

    def test_exception_returns_empty(self, mock_gcp):
        mock_gcp.list_pubsub_topics.side_effect = Exception("quota")
        with patch("cloudctl.commands.messaging.get_gcp_provider", return_value=mock_gcp):
            rows = _gcp_topic_rows(None)
        assert rows == []


class TestAwsStreamRows:
    def test_returns_kinesis_and_msk(self, fake_cfg, mock_aws):
        mock_aws.list_kinesis_streams.return_value = [_KIN]
        mock_aws.list_msk_clusters.return_value = [_MSK]
        with patch("cloudctl.commands.messaging.get_aws_provider", return_value=mock_aws):
            rows = _aws_stream_rows(fake_cfg, None, None)
        types = {r["Type"] for r in rows}
        assert "Kinesis" in types
        assert "MSK" in types

    def test_exception_skipped(self, fake_cfg, mock_aws):
        mock_aws.list_kinesis_streams.side_effect = Exception("creds")
        with patch("cloudctl.commands.messaging.get_aws_provider", return_value=mock_aws):
            rows = _aws_stream_rows(fake_cfg, None, None)
        assert rows == []


class TestAzureStreamRows:
    def test_returns_eventhub_row(self, mock_azure):
        mock_azure.list_event_hub_namespaces.return_value = [_EH]
        with patch("cloudctl.commands.messaging.get_azure_provider", return_value=mock_azure):
            rows = _azure_stream_rows(None, None)
        assert "Event Hubs" in rows[0]["Type"]

    def test_exception_returns_empty(self, mock_azure):
        mock_azure.list_event_hub_namespaces.side_effect = Exception("auth")
        with patch("cloudctl.commands.messaging.get_azure_provider", return_value=mock_azure):
            rows = _azure_stream_rows(None, None)
        assert rows == []


class TestGcpStreamRows:
    def test_returns_pubsub_sub_row(self, mock_gcp):
        mock_gcp.list_pubsub_subscriptions.return_value = [_PSS]
        with patch("cloudctl.commands.messaging.get_gcp_provider", return_value=mock_gcp):
            rows = _gcp_stream_rows(None)
        assert rows[0]["Type"] == "Pub/Sub Sub"

    def test_exception_returns_empty(self, mock_gcp):
        mock_gcp.list_pubsub_subscriptions.side_effect = Exception("quota")
        with patch("cloudctl.commands.messaging.get_gcp_provider", return_value=mock_gcp):
            rows = _gcp_stream_rows(None)
        assert rows == []
