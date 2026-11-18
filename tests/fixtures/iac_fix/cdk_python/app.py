import aws_cdk as cdk

from stacks.orders_stack import OrdersStack

app = cdk.App()
OrdersStack(app, "OrdersStack")
app.synth()
