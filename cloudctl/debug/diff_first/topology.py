"""The app's wiring, built from the expected state (or discovered resources).

Two kinds of edge:

* flow edges: work moves along them (queue -> event-source mapping -> function,
  bus -> rule -> target, function -> queue it writes to). Built from a small
  table of connector types and from a function's environment references.
* reference edges: everything else one resource points at (a function's role,
  a role policy's role, a permission's function). They decide which config can
  affect a component.

The tables below name resource TYPES and which attribute points where. They
hold no failure knowledge: nothing says what a broken X looks like.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cloudctl.debug.diff_first.model import Resource
from cloudctl.debug.diff_first.normalize import (
    ATTACHMENT_TYPES, get_field, identifiers_in, is_observer, norm_key,
)
from cloudctl.debug.diff_first.resolve import Resolver

# Connector types: they move work from a source to a destination. (source
# attribute names, destination attribute names), any spelling.
CONNECTORS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "AWS::Lambda::EventSourceMapping": (("event_source_arn", "EventSourceArn"), ("function_name", "FunctionName", "FunctionArn")),
    "AWS::Events::Target": (("rule",), ("arn",)),
    "AWS::Events::Rule": (("event_bus_name", "EventBusName"), ("targets",)),
    "AWS::SNS::Subscription": (("topic_arn", "TopicArn"), ("endpoint", "Endpoint")),
    "AWS::ApiGatewayV2::Integration": (("api_id", "ApiId"), ("integration_uri", "IntegrationUri")),
    "AWS::Pipes::Pipe": (("source", "Source"), ("target", "Target")),
    "AWS::S3::BucketNotification": (("bucket", "Bucket"), ("lambda_function", "queue", "topic", "LambdaConfigurations", "QueueConfigurations", "TopicConfigurations")),
}

# Where a failed unit of work goes (dead-letter / on-failure).
REDRIVE_FIELDS = ("redrive_policy", "RedrivePolicy", "dead_letter_config", "DeadLetterConfig",
                  "destination_config", "DestinationConfig")

# Types that carry work and so can sit on a flow edge.
FLOW_TYPES = {
    "AWS::Lambda::Function", "AWS::SQS::Queue", "AWS::SNS::Topic", "AWS::Events::EventBus",
    "AWS::Events::Rule", "AWS::DynamoDB::Table", "AWS::S3::Bucket", "AWS::Kinesis::Stream",
    "AWS::StepFunctions::StateMachine", "AWS::ApiGatewayV2::Api", "AWS::ECS::Service",
} | set(CONNECTORS)

# Types whose own code decides what to call (an "actor" writes to what its
# config names; a connector routes on its own config).
ACTOR_TYPES = {"AWS::Lambda::Function", "AWS::ECS::Service", "AWS::StepFunctions::StateMachine"}


@dataclass
class Topology:
    resources: dict[str, Resource]
    flow: dict[str, set[str]] = field(default_factory=dict)        # src -> dsts
    flow_rev: dict[str, set[str]] = field(default_factory=dict)
    redrive: dict[str, set[str]] = field(default_factory=dict)     # source -> dead-letter target
    refs: dict[str, set[str]] = field(default_factory=dict)        # a -> things a references (non-flow)
    refs_rev: dict[str, set[str]] = field(default_factory=dict)
    edge_kind: dict[tuple[str, str], str] = field(default_factory=dict)
    dangling: dict[str, list[str]] = field(default_factory=dict)   # key -> unresolved ARN/URL values

    # building -------------------------------------------------------------
    def add_flow(self, a: str, b: str, kind: str) -> None:
        if a == b or not a or not b:
            return
        self.flow.setdefault(a, set()).add(b)
        self.flow_rev.setdefault(b, set()).add(a)
        self.edge_kind[(a, b)] = kind

    def add_ref(self, a: str, b: str) -> None:
        if a == b or not a or not b:
            return
        self.refs.setdefault(a, set()).add(b)
        self.refs_rev.setdefault(b, set()).add(a)

    # queries --------------------------------------------------------------
    def type_of(self, key: str) -> str:
        r = self.resources.get(key)
        return r.type if r else ""

    def is_connector(self, key: str) -> bool:
        return self.type_of(key) in CONNECTORS

    def config_scope(self, key: str) -> set[str]:
        """Everything whose config can change how ``key`` behaves: itself, what it
        references (role, key, layer...), attachments on those (role policies,
        permissions) and the connectors that feed it. Observers are excluded."""
        out = {key}
        direct = set(self.refs.get(key, set()))
        out |= direct
        for x in direct | {key}:
            for y in self.refs_rev.get(x, set()):
                if self.type_of(y) in ATTACHMENT_TYPES:
                    out.add(y)
        for c in self.flow_rev.get(key, set()):
            if self.is_connector(c):
                out.add(c)
        return {k for k in out if not is_observer(self.type_of(k))}

    def downstream(self, key: str) -> set[str]:
        return set(self.flow.get(key, set()))

    def upstream(self, key: str) -> set[str]:
        return set(self.flow_rev.get(key, set()))

    def neighbours(self, key: str) -> set[str]:
        return (self.flow.get(key, set()) | self.flow_rev.get(key, set()) |
                self.refs.get(key, set()) | self.refs_rev.get(key, set()) |
                self.redrive.get(key, set()) |
                {s for s, ts in self.redrive.items() if key in ts})

    def components(self) -> list[set[str]]:
        seen: set[str] = set()
        comps: list[set[str]] = []
        for k in self.resources:
            if k in seen:
                continue
            stack, comp = [k], set()
            while stack:
                n = stack.pop()
                if n in comp:
                    continue
                comp.add(n)
                stack.extend(self.neighbours(n) - comp)
            seen |= comp
            comps.append(comp)
        return comps

    def to_dict(self) -> dict:
        return {
            "flow_edges": sorted([a, b, self.edge_kind.get((a, b), "")] for a, ts in self.flow.items() for b in ts),
            "redrive": sorted([a, b] for a, ts in self.redrive.items() for b in ts),
            "dangling_references": self.dangling,
        }


def _cfn_logicals(value, depth: int = 0) -> set[str]:
    """Logical ids referenced by CloudFormation intrinsics (Ref / GetAtt / Sub)."""
    import re
    out: set[str] = set()
    if depth > 8:
        return out
    if isinstance(value, dict):
        for k, v in value.items():
            if k == "Ref" and isinstance(v, str):
                out.add(v)
            elif k == "Fn::GetAtt":
                if isinstance(v, list) and v:
                    out.add(str(v[0]))
                elif isinstance(v, str):
                    out.add(v.split(".")[0])
            elif k == "Fn::Sub":
                s = v[0] if isinstance(v, list) and v else v
                if isinstance(s, str):
                    out |= {m.split(".")[0] for m in re.findall(r"\$\{([A-Za-z0-9.]+)\}", s)}
                out |= _cfn_logicals(v, depth + 1)
            else:
                out |= _cfn_logicals(v, depth + 1)
    elif isinstance(value, list):
        for v in value:
            out |= _cfn_logicals(v, depth + 1)
    return out


def _resolve(value, owner: Resource, resources: dict[str, Resource], rs: Resolver,
             hint: str = "") -> set[str]:
    """Resource keys a value points at (ARNs, URLs, names, CFN intrinsics)."""
    keys = rs.resolve(value, owner, hint)
    if owner.source in ("cloudformation", "cdk") and "/" in owner.key:
        stack = owner.key.split("/", 1)[0]
        for logical in _cfn_logicals(value):
            k = f"{stack}/{logical}"
            if k in resources:
                keys.add(k)
    keys.discard(owner.key)
    return keys


def _dangling(value, rs: Resolver) -> list[str]:
    """ARNs / queue URLs in a value that name no known resource."""
    from cloudctl.debug.diff_first.normalize import _ARN_RE, _URL_RE
    out: list[str] = []
    for tok in identifiers_in(value):
        if (_ARN_RE.fullmatch(tok) or _URL_RE.fullmatch(tok)) and not rs.resolve_str(tok):
            out.append(tok)
    return out


def build_topology(resources: dict[str, Resource]) -> Topology:
    topo = Topology(resources=resources)
    rs = Resolver(resources)
    for k, r in resources.items():
        cfg = r.config or {}
        flow_targets: set[str] = set()
        if r.type in CONNECTORS:
            src_f, dst_f = CONNECTORS[r.type]
            srcs = _resolve(get_field(cfg, *src_f), r, resources, rs, src_f[0])
            dsts = _resolve(get_field(cfg, *dst_f), r, resources, rs, dst_f[0])
            if r.type == "AWS::Events::Rule" and not srcs:
                # A rule without a bus name listens on the default bus.
                srcs = {x for x in resources if resources[x].type == "AWS::Events::EventBus"
                        and resources[x].name == "default"}
            for s in srcs:
                topo.add_flow(s, k, "connector")
            for d in dsts:
                topo.add_flow(k, d, "connector")
            flow_targets |= srcs | dsts
        if r.type in ACTOR_TYPES:
            env = get_field(cfg, "environment", "Environment")
            if env is not None:
                for d in _resolve(env, r, resources, rs):
                    if resources[d].type in FLOW_TYPES and resources[d].type not in CONNECTORS:
                        topo.add_flow(k, d, "writes")
                        flow_targets.add(d)
                # identifiers that look like ARNs/URLs but match nothing known
                miss = _dangling(env, rs)
                if miss:
                    topo.dangling[k] = miss[:5]
        for f in REDRIVE_FIELDS:
            v = get_field(cfg, f)
            if v:
                for d in _resolve(v, r, resources, rs, f):
                    topo.redrive.setdefault(k, set()).add(d)
                    flow_targets.add(d)
        # every other pointer is a reference edge
        for d in _resolve(cfg, r, resources, rs) - flow_targets:
            topo.add_ref(k, d)
    # Event targets (Terraform) point at their rule; give the rule the flow too.
    return topo


def service_of_type(cfn_type: str) -> str:
    parts = cfn_type.split("::")
    return norm_key(parts[1]) if len(parts) >= 2 else ""


def services_in(value) -> set[str]:
    """AWS services named by ARNs / queue URLs inside a value (sqs, lambda, ...)."""
    from cloudctl.debug.diff_first.normalize import _ARN_RE, _URL_RE
    out: set[str] = set()
    for tok in identifiers_in(value):
        if _URL_RE.fullmatch(tok):
            out.add("sqs")
        elif _ARN_RE.fullmatch(tok):
            out.add(norm_key(tok.split(":")[2]))
    return out
