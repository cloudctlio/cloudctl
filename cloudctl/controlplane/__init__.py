"""The control plane: request compiler, change graph, orchestrator.

    request ──▶ compiler ──▶ change graph ──▶ orchestrator ──▶ policy gate (per node) ──▶ executor
                (model +        (fixed JSON      (dependency       (credentials, plan,         (applies the
                 layered         schema, DAG)     order, no         policy, approval,           approved plan
                 validation)                      blind retry)      single-use authorization)   only)
"""
