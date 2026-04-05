"""
4xx Lambda — returns 403 Forbidden every time.
Simulates a misconfigured IAM policy or missing auth header.
CloudTrail will show the Lambda invocation succeeding (Lambda itself runs fine),
but the application-level auth check fails.
"""
import json


def handler(event, context):
    # Log the attempt — visible in CloudWatch Logs
    print(f"[ERROR] Access denied for path={event.get('rawPath', '/')} "
          f"identity={event.get('requestContext', {}).get('identity', {})}")

    return {
        "statusCode": 403,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({
            "error":   "Forbidden",
            "message": "User does not have permission to call this API. "
                       "Verify your IAM role has lambda:InvokeFunction and "
                       "the resource policy allows your account.",
            "code":    403,
        }),
    }
