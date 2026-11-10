"""Propose-then-verify debugging (design: "cctl: model-independent verdicts").

The model proposes candidate causes as falsifiable predictions written in a
small, fixed set of architecture-agnostic primitives; deterministic code in this
package runs them over a discovered model of the org's system and decides which
cause, if any, is verified. Nothing here knows which model is running or what
any particular failure looks like.

Modules
-------
model       SystemModel: nodes and edges with provenance (declared / live / observed)
iac         Terraform state and plan JSON, CloudFormation and CDK synth -> declared layer
observed    CloudTrail, VPC flow logs, X-Ray and log lines -> observed edges
evidence    EvidenceSource protocol and a fixture-backed implementation
primitives  The nine primitives: signal, config, drift, changed, before, permit,
            reach, path_health, peer
verifier    Schema checks, the five verification rules, the decision and the
            K-round propose/verify loop
profiles    Per-model settings loaded from profiles.yaml (data, not code)
proposer    Provider-neutral proposer call with structured output modes
remediation Read-only plan check, stubbed behind a flag until it is approved
shadow      Runs the verifier beside agent mode and logs what it would verify

Status: shadow mode only. Agent mode's verdict is never changed by this package.
"""
