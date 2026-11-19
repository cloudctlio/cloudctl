"""Diff-first debugging: deterministic checks that run BEFORE any hypothesis.

A good SRE starts from "what is different from normal". For an IaC-managed app
"normal" is already written down; without IaC it is the last known-good
snapshot. This package:

1. reads the expected state from whatever IaC the user has (Terraform,
   CloudFormation/CDK, Pulumi) through pluggable adapters, or falls back to a
   last-known-good baseline (AWS Config history or cctl's own snapshot), and
   diffs live config against it (``drift``);
2. finds when the symptom started and the last healthy point from metrics,
   and keeps only changes made inside that window that still hold
   (``window``, ``changes``);
3. builds the app's wiring and checks that work moves along every edge,
   flagging edges that went quiet (``flow``);
4. requires the answer to explain every observed symptom, with the cause
   before the symptom, and supports several concurrent causes (``explain``).

Everything here is plain logic: no model call, no per-service failure
knowledge base, read-only against AWS. The model's job afterwards shrinks to
ranking and explaining what these checks found.
"""

from cloudctl.debug.diff_first.run import (  # noqa: F401
    DiffFirstReport,
    run_diff_first,
    apply_to_report,
)
