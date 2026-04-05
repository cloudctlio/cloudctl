"""Debug resolver — builds IaC-aware resolution steps."""
from __future__ import annotations


_STEPS: dict[str, list[str]] = {
    # ── AWS ────────────────────────────────────────────────────────────────
    "cdk": [
        "Revert the change in your CDK code (check the relevant stack construct).",
        "Deploy through CodePipeline / your pipeline: push the revert commit and let it run.",
        "If the pipeline is unavailable: run `cdk deploy <stack>` locally with the reverted code.",
        "After deploying: update CDK code to match the expected state going forward.",
    ],
    "cloudformation": [
        "Update your CloudFormation template to revert the change.",
        "Deploy: `aws cloudformation update-stack --stack-name <stack> --template-body file://template.yaml`.",
        "Or use the CloudFormation console: select the stack → Update → Replace current template.",
    ],
    "codepipeline": [
        "Re-run the pipeline with the previous artifact (Release change → select previous revision).",
        "Or revert the source commit that triggered the failing deployment and push.",
    ],
    # ── Cross-cloud IaC ────────────────────────────────────────────────────
    "terraform": [
        "Revert the change in your Terraform code.",
        "Apply through your pipeline: push and trigger a plan/apply run.",
        "If the pipeline is unavailable: run `terraform apply -target=<resource>` with reverted code.",
        "If using Terraform Cloud/Enterprise: trigger a run from the workspace.",
    ],
    "pulumi": [
        "Revert the change in your Pulumi program.",
        "Run through your pipeline: push and trigger `pulumi up`.",
        "If the pipeline is unavailable: run `pulumi up` locally targeting the affected resource.",
    ],
    # ── Azure ──────────────────────────────────────────────────────────────
    "bicep": [
        "Revert the change in your Bicep file (.bicep).",
        "Redeploy: `az deployment group create --resource-group <rg> --template-file <file>.bicep`.",
        "Or trigger your CI/CD pipeline to redeploy the Bicep template.",
        "After deploying: ensure the Bicep source matches the live state to prevent drift.",
    ],
    "arm": [
        "Revert the change in your ARM template (azuredeploy.json or equivalent).",
        "Redeploy: `az deployment group create --resource-group <rg> --template-file azuredeploy.json`.",
        "Or use the Azure Portal: search 'Deploy a custom template' and upload the reverted template.",
    ],
    "azure-devops": [
        "Re-run the Azure DevOps pipeline with the previous artifact or pipeline revision.",
        "Or revert the source commit that triggered the failing pipeline and push to the target branch.",
        "In Azure DevOps: Pipelines → select pipeline → Runs → previous run → Re-run.",
    ],
    # ── GCP ────────────────────────────────────────────────────────────────
    "deployment-manager": [
        "Revert the change in your Deployment Manager config (.yaml or .jinja).",
        "Update the deployment: `gcloud deployment-manager deployments update <deployment> --config <file>.yaml`.",
        "Or use preview mode first: add `--preview` flag to verify before applying.",
    ],
    "config-connector": [
        "Do NOT make direct changes to the GCP resource — Config Connector will reconcile them back.",
        "Edit the Kubernetes Custom Resource (CR) instead: `kubectl edit <kind> <name> -n <namespace>`.",
        "Apply the change: `kubectl apply -f <resource>.yaml`.",
        "Config Connector will reconcile the GCP resource to match the CR within seconds.",
    ],
    "cloud-build": [
        "Re-trigger the Cloud Build trigger with the previous commit or artifact.",
        "Or revert the source commit and push to the trigger branch.",
        "In Cloud Build: go to Triggers → Run trigger → select the previous commit.",
    ],
    # ── CI/CD (cloud-agnostic) ─────────────────────────────────────────────
    "github-actions": [
        "Revert the commit that triggered the bad deployment and push to the deployment branch.",
        "Or manually re-trigger the workflow with the previous commit SHA.",
    ],
    # ── Fallback ───────────────────────────────────────────────────────────
    "unknown": [
        "Verify how this resource is managed before making changes.",
        "Check: CloudFormation/ARM/Deployment Manager stack? Terraform state? Resource tags/labels?",
        "Once confirmed, follow the process for that tool to revert the change.",
    ],
}


def build_steps(
    deployment_method: str,
    ai_steps: list[str],
) -> list[str]:
    """
    Merge AI-generated resolution steps with IaC-specific deployment steps.
    AI steps come first (what to change), IaC steps come after (how to deploy).
    """
    method   = (deployment_method or "unknown").lower()
    iac_steps = _STEPS.get(method, _STEPS["unknown"])

    combined: list[str] = list(ai_steps)

    # Avoid duplicating steps the AI already mentioned
    ai_text = " ".join(ai_steps).lower()
    for step in iac_steps:
        key = step.split(":")[0].lower()[:30]
        if key not in ai_text:
            combined.append(step)

    return combined
