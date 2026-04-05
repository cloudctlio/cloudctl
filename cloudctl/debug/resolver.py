"""Debug resolver — builds IaC-aware resolution steps."""
from __future__ import annotations


_STEPS: dict[str, list[str]] = {
    "cdk": [
        "Revert the change in your CDK code (check the relevant stack construct).",
        "Deploy through CodePipeline / your pipeline: push the revert commit and let it run.",
        "If the pipeline is unavailable: run `cdk deploy <stack>` locally with the reverted code.",
        "After deploying: update CDK code to match the expected state going forward.",
    ],
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
    "cloudformation": [
        "Update your CloudFormation template to revert the change.",
        "Deploy the updated stack: `aws cloudformation update-stack --stack-name <stack> --template-body file://template.yaml`.",
        "Or use the CloudFormation console: select the stack → Update → Replace current template.",
    ],
    "codepipeline": [
        "Re-run the pipeline with the previous artifact (Release change → select previous revision).",
        "Or revert the source commit that triggered the failing deployment and push.",
    ],
    "github-actions": [
        "Revert the commit that triggered the bad deployment and push to the deployment branch.",
        "Or manually re-trigger the workflow with the previous commit SHA.",
    ],
    "unknown": [
        "Verify how this resource is managed before making changes.",
        "Check: CloudFormation stack membership? Terraform state? Resource tags?",
        "Once confirmed, follow the process for that tool to revert the change.",
    ],
}

_GENERIC_STEPS = [
    "Identify the root cause and affected resources from the analysis above.",
    "Follow the IaC/deployment-specific steps listed below.",
    "Validate the fix by monitoring ALB error rates, ECS task health, and CloudWatch alarms.",
    "Update runbooks and add a CloudWatch alarm to detect this class of issue earlier.",
]


def build_steps(
    deployment_method: str,
    ai_steps: list[str],
) -> list[str]:
    """
    Merge AI-generated resolution steps with IaC-specific deployment steps.
    AI steps come first (what to change), IaC steps come after (how to deploy).
    """
    method = deployment_method.lower() if deployment_method else "unknown"
    iac_steps = _STEPS.get(method, _STEPS["unknown"])

    combined: list[str] = []
    combined.extend(ai_steps)

    # Avoid duplicating if AI already mentioned deployment steps
    ai_text = " ".join(ai_steps).lower()
    for step in iac_steps:
        key = step.split(":")[0].lower()[:30]
        if key not in ai_text:
            combined.append(step)

    return combined
