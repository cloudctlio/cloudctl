"""Back-to-back harness timeline, as e2e/complex-app/run.py runs it live.

The idealized fixtures in diff_first_fixtures.py give each scenario three
quiet hours and inject the fault 15 minutes before the run. The live harness
runs scenarios back to back in one deployment: deploy, s1, s3, s4, then s5
(or s4 last), each fault reverted with terraform apply and a queue purge, the
next one injected a minute or two before cctl starts. CloudWatch then lags the
fault by ~3 minutes and still shows the previous scenario's symptoms, and
CloudTrail has not delivered the newest change yet. This builds that timeline
so the two failures from live run 3 (s4, s5) replay offline.
"""
from __future__ import annotations

import diff_first_fixtures as fx
from diff_first_fixtures import ACCT, API_ID, P, PATTERN_BAD, PATTERN_OK, REGION, ev, t, worker_policy

def series(fn, born=None):
    """fn(ago) -> value for one-minute buckets 180..0 minutes ago; no point
    before ``born`` minutes ago (the resource did not exist yet)."""
    out = []
    for i in range(181):
        ago = 180 - i
        if born is not None and ago > born:
            continue
        out.append([t(ago), round(max(fn(ago), 0.0), 3)])
    return out

def build(last="s5", deploy_ago=60, inj_ago=2.5, run3=False, busy_api=False):
    """(terraform state, RecordedLive data) for a run started ``inj_ago``
    minutes after the last scenario's fault was injected.

    ``run3`` matches live run 3 more closely: the s4 load hit the Lambda
    concurrency limit, so the api returned 5xx all through it, and the s3
    revert and its queue purge landed seconds after that load began.

    ``busy_api`` matches the second PR 47 rerun: the api sat at the Lambda
    concurrency limit from its very first traffic, so its 5xx were never zero
    while load ran (a standing condition, not an incident onset)."""
    # load windows (from_ago, to_ago, profile)
    if last == "s5":
        loads = {"s1": (55, 46), "s3": (44, 35), "s4": (33, 4), "s5": (inj_ago, 0)}
    else:  # s4 is the last scenario
        loads = {"s1": (55, 46), "s3": (44, 35), "s4": (inj_ago, 0)}
    if run3 and last == "s5":
        # healthy traffic between s3's revert and the s4 load
        loads.update({"s3": (44, 37), "gap": (37, 33.01)})
    def in_load(ago, sid):
        a, b = loads.get(sid, (None, None))
        return a is not None and b <= ago <= a
    def active(ago):
        return any(in_load(ago, s) for s in loads)
    rps = 6
    def api_count(ago): return rps * 60 if active(ago) else 0
    def post(ago): return 0.6 * api_count(ago)
    def api_5xx(ago):
        if in_load(ago, "s3"): return post(ago)
        if busy_api: return 0.3 * post(ago)
        # run 3: the api stayed at the concurrency limit from the s4 load on
        return 0.3 * post(ago) if run3 and (in_load(ago, "s4") or in_load(ago, "s5")) else 0
    def q_sent(ago): return 0 if in_load(ago, "s3") else post(ago)
    def w_inv(ago):
        if in_load(ago, "s5"): return 0
        return q_sent(ago) * (1.3 if in_load(ago, "s4") or in_load(ago, "s1") else 1)
    def w_err(ago):
        # The second rerun's replay showed no worker Lambda errors during s1
        # (baseline 0, first rise at s4), so busy_api leaves them out.
        if in_load(ago, "s1"): return 0 if busy_api else 0.2 * q_sent(ago) * 3
        if in_load(ago, "s4"): return 0.35 * q_sent(ago) * 3
        return 0
    def deleted(ago): return 0 if in_load(ago, "s5") else q_sent(ago) * 0.8
    def matched(ago):
        if in_load(ago, "s4"): return 0
        return q_sent(ago) * 0.8 if not in_load(ago, "s5") else 0
    def visible(ago):
        if in_load(ago, "s5"): return post(ago) * (inj_ago - ago)
        return 1 if active(ago) else 0
    def dlq(ago):
        if in_load(ago, "s1"): return 2 * (55 - ago)
        if in_load(ago, "s4"): return 3 * (33 - ago)
        return 0
    L, S, E = "AWS::Lambda::Function", "AWS::SQS::Queue", "AWS::Events::Rule"
    m = lambda typ, name, metric: f"{typ}|{name}|{metric}"
    mets = {
        m("AWS::ApiGatewayV2::Api", API_ID, "Count"): series(api_count),
        m("AWS::ApiGatewayV2::Api", API_ID, "5xx"): series(api_5xx),
        m(L, f"{P}-api", "Invocations"): series(api_count),
        m(L, f"{P}-api", "Errors"): series(api_5xx),
        m(S, f"{P}-orders", "NumberOfMessagesSent"): series(q_sent),
        m(S, f"{P}-orders", "NumberOfMessagesDeleted"): series(deleted),
        m(S, f"{P}-orders", "ApproximateNumberOfMessagesVisible"): series(visible, born=deploy_ago),
        m(S, f"{P}-orders-dlq", "NumberOfMessagesSent"): series(lambda a: 0),
        m(S, f"{P}-orders-dlq", "ApproximateNumberOfMessagesVisible"): series(dlq, born=deploy_ago),
        m(L, f"{P}-worker", "Invocations"): series(w_inv),
        m(L, f"{P}-worker", "Errors"): series(w_err),
        m(L, f"{P}-worker", "Throttles"): series(lambda a: 0),
        m(E, f"{P}-order-processed", "MatchedEvents"): series(matched),
        m(E, f"{P}-order-processed", "FailedInvocations"): series(lambda a: 0),
        m(L, f"{P}-notifier", "Invocations"): series(matched),
        m(L, f"{P}-notifier", "Errors"): series(lambda a: 0),
        m("AWS::DynamoDB::Table", f"{P}-orders", "ConsumedWriteCapacityUnits"): series(lambda a: 3 * post(a)),
    }
    bad_env = {"TABLE_NAME": f"{P}-orders", "QUEUE_URL": f"https://sqs.{REGION}.amazonaws.com/{ACCT}/{P}-orders-v2",
               "CACHE_ENDPOINT": "redis://127.0.0.1:6379"}
    good_env = {"TABLE_NAME": f"{P}-orders", "QUEUE_URL": fx.Q_URL}
    lam = "lambda.amazonaws.com"
    D = deploy_ago
    events = fx.background_events() + [
        ev(D, "CreateTable", "dynamodb.amazonaws.com", {"tableName": f"{P}-orders", "billingMode": "PAY_PER_REQUEST"}),
        ev(D, "CreateQueue", "sqs.amazonaws.com", {"queueName": f"{P}-orders-dlq"}),
        ev(D, "CreateQueue", "sqs.amazonaws.com", {"queueName": f"{P}-orders", "attributes": {"VisibilityTimeout": "30"}}),
        ev(D, "CreateRole", "iam.amazonaws.com", {"roleName": f"{P}-worker-role"}),
        ev(D, "PutRolePolicy", "iam.amazonaws.com", {"roleName": f"{P}-worker-role", "policyName": f"{P}-worker-policy", "policyDocument": worker_policy("receipts")}),
        ev(D, "CreateFunction20150331", lam, {"functionName": f"{P}-worker", "timeout": 10, "memorySize": 256}),
        ev(D, "CreateFunction20150331", lam, {"functionName": f"{P}-api", "timeout": 10, "environment": {"variables": good_env}}),
        ev(D, "CreateFunction20150331", lam, {"functionName": f"{P}-notifier", "timeout": 10}),
        ev(D - 0.5, "CreateEventSourceMapping20150331", lam, {"functionName": f"{P}-worker", "eventSourceArn": fx.arn("sqs", f"{P}-orders"), "batchSize": 1, "enabled": True}),
        ev(D - 0.5, "PutRule", "events.amazonaws.com", {"name": f"{P}-order-processed", "eventBusName": f"{P}-bus", "eventPattern": PATTERN_OK}),
        # s1
        ev(55.5, "PutRolePolicy", "iam.amazonaws.com", {"roleName": f"{P}-worker-role", "policyName": f"{P}-worker-policy", "policyDocument": worker_policy("invoices")}),
        ev(45.5, "PutRolePolicy", "iam.amazonaws.com", {"roleName": f"{P}-worker-role", "policyName": f"{P}-worker-policy", "policyDocument": worker_policy("receipts")}),
        ev(45, "PurgeQueue", "sqs.amazonaws.com", {"queueUrl": fx.Q_URL}),
        # s3
        ev(44.5, "UpdateFunctionConfiguration20150331v2", lam, {"functionName": f"{P}-api", "environment": {"variables": bad_env}}),
        ev(32.9 if run3 else 34.5, "UpdateFunctionConfiguration20150331v2", lam, {"functionName": f"{P}-api", "environment": {"variables": good_env}}),
        ev(32.75 if run3 else 34, "PurgeQueue", "sqs.amazonaws.com", {"queueUrl": fx.Q_URL}),
    ]
    if last == "s5":
        events += [
            ev(32.4 if run3 else 33.5, "UpdateFunctionConfiguration20150331v2", lam, {"functionName": f"{P}-worker", "timeout": 2}),
            ev(32.3 if run3 else 33.4, "PutRule", "events.amazonaws.com", {"name": f"{P}-order-processed", "eventBusName": f"{P}-bus", "eventPattern": PATTERN_BAD}),
            ev(3.5, "UpdateFunctionConfiguration20150331v2", lam, {"functionName": f"{P}-worker", "timeout": 10}),
            ev(3.4, "PutRule", "events.amazonaws.com", {"name": f"{P}-order-processed", "eventBusName": f"{P}-bus", "eventPattern": PATTERN_OK}),
            ev(3, "PurgeQueue", "sqs.amazonaws.com", {"queueUrl": fx.Q_URL}),
        ]
        # the UpdateEventSourceMapping at inj_ago is NOT in CloudTrail yet (delivery lag)
        state = fx.tf_state(fx.tf_attrs())
        live = fx.live_configs(esm_enabled=False)
    else:
        events += [
            ev(inj_ago + 0.3, "UpdateFunctionConfiguration20150331v2", lam, {"functionName": f"{P}-worker", "timeout": 2}),
            ev(inj_ago + 0.2, "PutRule", "events.amazonaws.com", {"name": f"{P}-order-processed", "eventBusName": f"{P}-bus", "eventPattern": PATTERN_BAD}),
        ]
        state = fx.tf_state(fx.tf_attrs(worker_timeout=2, rule_pattern=PATTERN_BAD))
        live = fx.live_configs(worker_timeout=2, rule_pattern=PATTERN_BAD)
    return state, {"now": t(0), "configs": live, "events": events, "metrics": mets}
