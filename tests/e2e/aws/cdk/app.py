#!/usr/bin/env python3
"""
CDK stack — deploys 4 Lambda + HTTP API Gateway test apps.

Deploy:
  pip install aws-cdk-lib constructs
  cdk bootstrap
  cdk deploy

Destroy:
  cdk destroy
"""
import aws_cdk as cdk
from constructs import Construct
from aws_cdk import (
    Stack,
    Duration,
    CfnOutput,
    aws_lambda as lambda_,
    aws_apigatewayv2 as apigw,
    aws_apigatewayv2_integrations as integrations,
    aws_logs as logs,
)


class CloudctlDebugTestStack(Stack):
    def __init__(self, scope: Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # HTTP API — single gateway, 4 routes
        http_api = apigw.HttpApi(
            self, "TestApi",
            api_name="cloudctl-debug-test",
            description="cloudctl debug test — 4 scenarios",
        )

        scenarios = {
            "healthy":      {"timeout": 5,  "memory": 128, "failure_rate": "0"},
            "error-5xx":    {"timeout": 10, "memory": 128, "failure_rate": "1"},
            "error-4xx":    {"timeout": 5,  "memory": 128, "failure_rate": "0"},
            "intermittent": {"timeout": 10, "memory": 128, "failure_rate": "0.5"},
        }

        for name, cfg in scenarios.items():
            # Use underscores for the handler directory name
            handler_dir = f"handlers/{name.replace('-', '_')}"

            log_group = logs.LogGroup(
                self, f"LogGroup-{name}",
                log_group_name=f"/aws/lambda/cloudctl-test-{name}",
                retention=logs.RetentionDays.ONE_WEEK,
            )

            fn = lambda_.Function(
                self, f"Fn-{name}",
                function_name=f"cloudctl-test-{name}",
                runtime=lambda_.Runtime.PYTHON_3_12,
                handler="handler.handler",
                code=lambda_.Code.from_asset(handler_dir),
                timeout=Duration.seconds(cfg["timeout"]),
                memory_size=cfg["memory"],
                log_group=log_group,
                environment={
                    "APP_NAME":    f"cloudctl-test-{name}",
                    "FAILURE_RATE": cfg["failure_rate"],
                },
            )

            http_api.add_routes(
                path=f"/{name}",
                methods=[apigw.HttpMethod.GET, apigw.HttpMethod.POST],
                integration=integrations.HttpLambdaIntegration(
                    f"Integration-{name}", fn
                ),
            )

            CfnOutput(self, f"Url-{name}", value=f"{http_api.url}{name}")

        CfnOutput(self, "ApiUrl", value=http_api.url or "")


app = cdk.App()
CloudctlDebugTestStack(
    app, "CloudctlDebugTestStack",
    env=cdk.Environment(
        account=app.node.try_get_context("account"),
        region=app.node.try_get_context("region") or "us-east-1",
    ),
    tags={
        "aws:cdk:path":  "CloudctlDebugTestStack",  # ensures CDK detection
        "project":       "cloudctl-debug-test",
        "managed-by":    "cdk",
    },
)
app.synth()
