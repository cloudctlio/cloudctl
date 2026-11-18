from aws_cdk import Stack, aws_dynamodb as dynamodb, aws_lambda as lambda_
from constructs import Construct


class OrdersStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        table = dynamodb.Table(
            self, "OrdersTable",
            table_name="orders",
            partition_key=dynamodb.Attribute(name="id", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PROVISIONED,
            read_capacity=5,
            write_capacity=1,
        )

        writer = lambda_.Function(
            self, "OrdersWriter",
            function_name="orders-writer",
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler="app.handler",
            code=lambda_.Code.from_inline("def handler(e, c):\n    return None\n"),
            environment={"TABLE_NAME": table.table_name},
        )
        table.grant_write_data(writer)
