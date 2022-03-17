import aws_cdk as core
import aws_cdk.assertions as assertions

from ecs_database_construct.ecs_database_construct_stack import EcsDatabaseConstructStack

# example tests. To run these tests, uncomment this file along with the example
# resource in ecs_database_construct/ecs_database_construct_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = EcsDatabaseConstructStack(app, "ecs-database-construct")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
