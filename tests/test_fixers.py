"""Tests for fixer logic — can_fix() pure logic and apply() with mocked SDKs."""
from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest


# ── Helpers: inject missing SDK modules via sys.modules ───────────────────────

def _azure_mods(network_client=None, storage_client=None, compute_client=None):
    """Return a sys.modules patch dict for Azure SDKs with controllable clients."""
    mock_cred = MagicMock()

    identity = MagicMock()
    identity.DefaultAzureCredential.return_value = mock_cred

    network = MagicMock()
    if network_client:
        network.NetworkManagementClient.return_value = network_client

    storage = MagicMock()
    if storage_client:
        storage.StorageManagementClient.return_value = storage_client

    compute = MagicMock()
    if compute_client:
        compute.ComputeManagementClient.return_value = compute_client

    mods = {
        "azure":                        MagicMock(),
        "azure.identity":               identity,
        "azure.mgmt":                   MagicMock(),
        "azure.mgmt.network":           network,
        "azure.mgmt.storage":           storage,
        "azure.mgmt.storage.models":    MagicMock(),
        "azure.mgmt.compute":           compute,
        "azure.mgmt.compute.models":    MagicMock(),
    }
    return mods, mock_cred


def _gcp_mods(svc=None):
    """Return a sys.modules patch dict for GCP SDKs with a controllable service."""
    google_auth = MagicMock()
    google_auth.default.return_value = (MagicMock(), "test-project")

    discovery = MagicMock()
    if svc:
        discovery.build.return_value = svc

    # Pre-wire parent→child so `import google.auth` and
    # `from googleapiclient import discovery` resolve our mocks.
    google_mock = MagicMock()
    google_mock.auth = google_auth

    googleapiclient_mock = MagicMock()
    googleapiclient_mock.discovery = discovery

    mods = {
        "google":                    google_mock,
        "google.auth":               google_auth,
        "googleapiclient":           googleapiclient_mock,
        "googleapiclient.discovery": discovery,
    }
    return mods, google_auth, discovery


# ── AWS security fixers ────────────────────────────────────────────────────────

class TestAWSOpenSecurityGroupFixer:
    @pytest.fixture(autouse=True)
    def fixer(self):
        from cloudctl.fixers.aws.security import AWSOpenSecurityGroupFixer
        self.f = AWSOpenSecurityGroupFixer()

    def test_can_fix_open_sg(self):
        assert self.f.can_fix({
            "resource": "sg/sg-abc123 (default)",
            "issue": "Security group allows all inbound traffic (0.0.0.0/0)",
        })

    def test_can_fix_open_sg_alternate_text(self):
        assert self.f.can_fix({
            "resource": "sg/sg-xyz (my-sg)",
            "issue": "open security group",
        })

    def test_cannot_fix_unrelated(self):
        assert not self.f.can_fix({
            "resource": "s3://my-bucket",
            "issue": "public bucket",
        })

    def test_cannot_fix_no_sg_in_resource(self):
        assert not self.f.can_fix({
            "resource": "ec2/i-12345",
            "issue": "idle instance",
        })

    def test_apply_revokes_open_rules(self):
        mock_ec2 = MagicMock()
        mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [{
                "GroupId": "sg-abc123",
                "IpPermissions": [{"IpRanges": [{"CidrIp": "0.0.0.0/0"}], "FromPort": -1}],
            }]
        }
        mock_session = MagicMock()
        mock_session.client.return_value = mock_ec2

        with patch("boto3.Session", return_value=mock_session):
            self.f.apply(
                {"resource": "sg/sg-abc123 (default)", "account": "prod", "region": "us-east-1"},
                {},
            )
        mock_ec2.revoke_security_group_ingress.assert_called_once()

    def test_apply_no_open_rules_skips_revoke(self):
        mock_ec2 = MagicMock()
        mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [{
                "GroupId": "sg-abc123",
                "IpPermissions": [{"IpRanges": [{"CidrIp": "10.0.0.0/8"}], "FromPort": 80}],
            }]
        }
        mock_session = MagicMock()
        mock_session.client.return_value = mock_ec2
        with patch("boto3.Session", return_value=mock_session):
            self.f.apply(
                {"resource": "sg/sg-abc123 (default)", "account": "prod", "region": None},
                {},
            )
        mock_ec2.revoke_security_group_ingress.assert_not_called()

    def test_apply_bad_resource_raises(self):
        with pytest.raises(ValueError, match="Could not parse"):
            self.f.apply({"resource": "no-sg-here", "account": "prod"}, {})


class TestAWSS3PublicAccessFixer:
    @pytest.fixture(autouse=True)
    def fixer(self):
        from cloudctl.fixers.aws.security import AWSS3PublicAccessFixer
        self.f = AWSS3PublicAccessFixer()

    def test_can_fix_public_s3(self):
        assert self.f.can_fix({
            "resource": "s3/my-bucket",
            "issue": "bucket is publicly accessible",
        })

    def test_cannot_fix_sg(self):
        assert not self.f.can_fix({
            "resource": "sg/sg-1 (default)",
            "issue": "open security group",
        })

    def test_apply_blocks_public_access(self):
        mock_s3   = MagicMock()
        mock_sess = MagicMock()
        mock_sess.client.return_value = mock_s3

        with patch("boto3.Session", return_value=mock_sess):
            self.f.apply({"resource": "s3/my-bucket", "account": "prod"}, {})

        mock_s3.put_public_access_block.assert_called_once()
        config = mock_s3.put_public_access_block.call_args[1]["PublicAccessBlockConfiguration"]
        assert config["BlockPublicAcls"] is True
        assert config["RestrictPublicBuckets"] is True

    def test_apply_uses_bucket_name_from_resource(self):
        mock_s3   = MagicMock()
        mock_sess = MagicMock()
        mock_sess.client.return_value = mock_s3
        with patch("boto3.Session", return_value=mock_sess):
            self.f.apply({"resource": "s3/prod-data-lake", "account": "prod"}, {})
        call_kwargs = mock_s3.put_public_access_block.call_args[1]
        assert call_kwargs["Bucket"] == "prod-data-lake"


class TestAWSIAMOldKeyFixer:
    @pytest.fixture(autouse=True)
    def fixer(self):
        from cloudctl.fixers.aws.security import AWSIAMOldKeyFixer
        self.f = AWSIAMOldKeyFixer()

    def test_can_fix_old_key(self):
        assert self.f.can_fix({
            "resource": "iam/user/alice/access-key",
            "issue": "access key is 120 days old",
        })

    def test_can_fix_rotation_required(self):
        assert self.f.can_fix({
            "resource": "iam/user/alice/access-key",
            "issue": "access key rotation required",
        })

    def test_cannot_fix_unrelated(self):
        assert not self.f.can_fix({"resource": "s3/bucket", "issue": "public bucket"})

    def test_apply_deactivates_key(self):
        mock_iam  = MagicMock()
        mock_sess = MagicMock()
        mock_sess.client.return_value = mock_iam

        with patch("boto3.Session", return_value=mock_sess):
            self.f.apply(
                {"resource": "iam/user/alice", "account": "prod", "key_id": "test-key-id"},
                {},
            )
        mock_iam.update_access_key.assert_called_once_with(
            AccessKeyId="test-key-id", Status="Inactive"
        )

    def test_apply_bad_resource_raises(self):
        with pytest.raises(ValueError, match="Could not parse"):
            self.f.apply({"resource": "no-key-here", "account": "prod"}, {})


# ── AWS cost fixers ────────────────────────────────────────────────────────────

class TestAWSStopIdleInstanceFixer:
    @pytest.fixture(autouse=True)
    def fixer(self):
        from cloudctl.fixers.aws.cost import AWSStopIdleInstanceFixer
        self.f = AWSStopIdleInstanceFixer()

    def test_can_fix_idle_ec2(self):
        assert self.f.can_fix({"resource": "ec2/i-12345", "issue": "idle instance, CPU < 1%"})

    def test_can_fix_unused_instance(self):
        assert self.f.can_fix({"resource": "i-abc123 (web-server)", "issue": "unused instance"})

    def test_cannot_fix_rds(self):
        assert not self.f.can_fix({"resource": "rds/db-1", "issue": "idle database"})

    def test_apply_stops_instance(self):
        mock_ec2  = MagicMock()
        mock_sess = MagicMock()
        mock_sess.client.return_value = mock_ec2

        with patch("boto3.Session", return_value=mock_sess):
            self.f.apply(
                {"resource": "ec2/i-12345abc", "account": "prod", "region": "us-east-1"},
                {},
            )
        mock_ec2.stop_instances.assert_called_once_with(InstanceIds=["i-12345abc"])

    def test_apply_bad_resource_raises(self):
        with pytest.raises(ValueError):
            self.f.apply({"resource": "no-instance-id", "account": "prod"}, {})


class TestAWSDeleteOrphanedVolumeFixer:
    @pytest.fixture(autouse=True)
    def fixer(self):
        from cloudctl.fixers.aws.cost import AWSDeleteOrphanedVolumeFixer
        self.f = AWSDeleteOrphanedVolumeFixer()

    def test_can_fix_orphaned_vol(self):
        assert self.f.can_fix({"resource": "vol-0abc123", "issue": "unattached EBS volume"})

    def test_cannot_fix_compute(self):
        assert not self.f.can_fix({"resource": "i-1234", "issue": "idle instance"})

    def test_apply_deletes_volume(self):
        mock_ec2  = MagicMock()
        mock_sess = MagicMock()
        mock_sess.client.return_value = mock_ec2

        with patch("boto3.Session", return_value=mock_sess):
            self.f.apply({"resource": "vol-0abc123def", "account": "prod"}, {})
        mock_ec2.delete_volume.assert_called_once_with(VolumeId="vol-0abc123def")

    def test_apply_bad_resource_raises(self):
        with pytest.raises(ValueError):
            self.f.apply({"resource": "ebs-orphan-disk", "account": "prod"}, {})


class TestAWSDeleteOldSnapshotFixer:
    @pytest.fixture(autouse=True)
    def fixer(self):
        from cloudctl.fixers.aws.cost import AWSDeleteOldSnapshotFixer
        self.f = AWSDeleteOldSnapshotFixer()

    def test_can_fix_old_snapshot(self):
        assert self.f.can_fix({"resource": "snap-0abc123", "issue": "snapshot older than retention policy"})

    def test_cannot_fix_volume(self):
        assert not self.f.can_fix({"resource": "vol-0abc", "issue": "unattached"})

    def test_apply_deletes_snapshot(self):
        mock_ec2  = MagicMock()
        mock_sess = MagicMock()
        mock_sess.client.return_value = mock_ec2

        with patch("boto3.Session", return_value=mock_sess):
            self.f.apply({"resource": "snap-0abc123def", "account": "prod"}, {})
        mock_ec2.delete_snapshot.assert_called_once_with(SnapshotId="snap-0abc123def")

    def test_apply_bad_resource_raises(self):
        with pytest.raises(ValueError):
            self.f.apply({"resource": "backup-archive-image", "account": "prod"}, {})


# ── Azure security fixers ──────────────────────────────────────────────────────

class TestAzureNSGOpenRuleFixer:
    @pytest.fixture(autouse=True)
    def fixer(self):
        from cloudctl.fixers.azure.security import AzureNSGOpenRuleFixer
        self.f = AzureNSGOpenRuleFixer()

    def test_can_fix_open_nsg(self):
        assert self.f.can_fix({
            "resource": "resourceGroups/rg1/networkSecurityGroups/nsg1",
            "issue": "NSG allows any inbound traffic",
        })

    def test_cannot_fix_sg(self):
        assert not self.f.can_fix({"resource": "sg/sg-1", "issue": "open sg"})

    def test_apply_deletes_rule(self):
        mock_client = MagicMock()
        mods, _     = _azure_mods(network_client=mock_client)
        with patch.dict(sys.modules, mods):
            self.f.apply(
                {
                    "resource": "resourceGroups/rg1/networkSecurityGroups/nsg1",
                    "account":  "sub-1",
                    "issue":    "open nsg",
                },
                {"rule_name": "AllowAll"},
            )
        mock_client.security_rules.begin_delete.assert_called_once_with("rg1", "nsg1", "AllowAll")
        mock_client.security_rules.begin_delete.return_value.result.assert_called_once()

    def test_apply_no_rule_name_skips_delete(self):
        mock_client = MagicMock()
        mods, _     = _azure_mods(network_client=mock_client)
        with patch.dict(sys.modules, mods):
            self.f.apply(
                {"resource": "resourceGroups/rg1/networkSecurityGroups/nsg1", "account": "sub-1"},
                {},
            )
        mock_client.security_rules.begin_delete.assert_not_called()

    def test_apply_bad_resource_raises(self):
        mods, _ = _azure_mods()
        with patch.dict(sys.modules, mods):
            with pytest.raises(ValueError, match="Could not parse"):
                self.f.apply({"resource": "bad-resource", "account": "sub-1"}, {"rule_name": "x"})


class TestAzurePublicBlobFixer:
    @pytest.fixture(autouse=True)
    def fixer(self):
        from cloudctl.fixers.azure.security import AzurePublicBlobFixer
        self.f = AzurePublicBlobFixer()

    def test_can_fix_public_blob(self):
        assert self.f.can_fix({
            "resource": "resourceGroups/rg1/storageAccounts/myacct",
            "issue": "public blob access enabled",
        })

    def test_cannot_fix_nsg(self):
        assert not self.f.can_fix({"resource": "nsg/nsg-1", "issue": "open rule"})

    def test_apply_disables_public_access(self):
        mock_client = MagicMock()
        mods, _     = _azure_mods(storage_client=mock_client)
        with patch.dict(sys.modules, mods):
            self.f.apply(
                {"resource": "resourceGroups/rg1/storageAccounts/myacct", "account": "sub-1"},
                {},
            )
        mock_client.storage_accounts.update.assert_called_once()

    def test_apply_bad_resource_raises(self):
        mods, _ = _azure_mods()
        with patch.dict(sys.modules, mods):
            with pytest.raises(ValueError, match="Could not parse"):
                self.f.apply({"resource": "bad-resource", "account": "sub-1"}, {})


# ── Azure cost fixers ──────────────────────────────────────────────────────────

class TestAzureDeallocateIdleVMFixer:
    @pytest.fixture(autouse=True)
    def fixer(self):
        from cloudctl.fixers.azure.cost import AzureDeallocateIdleVMFixer
        self.f = AzureDeallocateIdleVMFixer()

    def test_can_fix_idle_vm(self):
        assert self.f.can_fix({
            "resource": "resourceGroups/rg1/virtualMachines/vm1",
            "issue": "VM is idle, CPU < 1%",
        })

    def test_cannot_fix_disk(self):
        assert not self.f.can_fix({"resource": "disks/disk-1", "issue": "unattached disk"})

    def test_apply_deallocates_vm(self):
        mock_client = MagicMock()
        mods, _     = _azure_mods(compute_client=mock_client)
        with patch.dict(sys.modules, mods):
            self.f.apply(
                {"resource": "resourceGroups/rg1/virtualMachines/vm1", "account": "sub-1"},
                {},
            )
        mock_client.virtual_machines.begin_deallocate.assert_called_once_with("rg1", "vm1")
        mock_client.virtual_machines.begin_deallocate.return_value.result.assert_called_once()

    def test_apply_bad_resource_raises(self):
        mods, _ = _azure_mods()
        with patch.dict(sys.modules, mods):
            with pytest.raises(ValueError, match="Could not parse"):
                self.f.apply({"resource": "bad-resource", "account": "sub-1"}, {})


class TestAzureDeleteOrphanedDiskFixer:
    @pytest.fixture(autouse=True)
    def fixer(self):
        from cloudctl.fixers.azure.cost import AzureDeleteOrphanedDiskFixer
        self.f = AzureDeleteOrphanedDiskFixer()

    def test_can_fix_unattached_disk(self):
        assert self.f.can_fix({
            "resource": "resourceGroups/rg1/disks/disk-1",
            "issue": "unattached managed disk",
        })

    def test_cannot_fix_vm(self):
        assert not self.f.can_fix({
            "resource": "virtualMachines/vm1",
            "issue": "idle vm",
        })

    def test_apply_deletes_disk(self):
        mock_client = MagicMock()
        mods, _     = _azure_mods(compute_client=mock_client)
        with patch.dict(sys.modules, mods):
            self.f.apply(
                {"resource": "resourceGroups/rg1/disks/disk-1", "account": "sub-1"},
                {},
            )
        mock_client.disks.begin_delete.assert_called_once_with("rg1", "disk-1")

    def test_apply_bad_resource_raises(self):
        mods, _ = _azure_mods()
        with patch.dict(sys.modules, mods):
            with pytest.raises(ValueError, match="Could not parse"):
                self.f.apply({"resource": "bad-resource", "account": "sub-1"}, {})


# ── GCP security fixers ────────────────────────────────────────────────────────

class TestGCPOpenFirewallFixer:
    @pytest.fixture(autouse=True)
    def fixer(self):
        from cloudctl.fixers.gcp.security import GCPOpenFirewallFixer
        self.f = GCPOpenFirewallFixer()

    def test_can_fix_open_firewall(self):
        assert self.f.can_fix({
            "resource": "firewalls/allow-all-inbound",
            "issue": "allows all traffic from 0.0.0.0/0",
        })

    def test_cannot_fix_bucket(self):
        assert not self.f.can_fix({"resource": "gs://my-bucket", "issue": "public bucket"})

    def test_apply_deletes_firewall_rule(self):
        mock_svc = MagicMock()
        mods, _, _ = _gcp_mods(svc=mock_svc)
        with patch.dict(sys.modules, mods):
            self.f.apply(
                {"resource": "firewalls/allow-all-inbound", "account": "my-project"},
                {},
            )
        mock_svc.firewalls().delete.assert_called_once_with(
            project="my-project", firewall="allow-all-inbound"
        )

    def test_apply_bad_resource_raises(self):
        mods, _, _ = _gcp_mods()
        with patch.dict(sys.modules, mods):
            with pytest.raises(ValueError, match="Could not parse"):
                self.f.apply({"resource": "no-gcp-fw-here", "account": "proj"}, {})


class TestGCPPublicBucketFixer:
    @pytest.fixture(autouse=True)
    def fixer(self):
        from cloudctl.fixers.gcp.security import GCPPublicBucketFixer
        self.f = GCPPublicBucketFixer()

    def test_can_fix_public_gcs(self):
        assert self.f.can_fix({"resource": "gs://my-bucket", "issue": "allUsers has access"})

    def test_cannot_fix_firewall(self):
        assert not self.f.can_fix({"resource": "firewalls/fw-1", "issue": "open firewall"})

    def test_apply_removes_public_bindings(self):
        mock_svc = MagicMock()
        # Set up the chained mock: svc.buckets().getIamPolicy(bucket=...).execute()
        mock_svc.buckets.return_value.getIamPolicy.return_value.execute.return_value = {
            "bindings": [
                {"role": "roles/storage.objectViewer", "members": ["allUsers"]},
                {"role": "roles/storage.admin",        "members": ["user:admin@example.com"]},
            ]
        }
        mods, _, _ = _gcp_mods(svc=mock_svc)
        with patch.dict(sys.modules, mods):
            self.f.apply({"resource": "gs://my-bucket", "account": "my-project"}, {})

        set_call     = mock_svc.buckets.return_value.setIamPolicy.call_args
        saved_policy = set_call[1]["body"]
        all_members  = [m for b in saved_policy["bindings"] for m in b["members"]]
        assert "allUsers" not in all_members
        assert "user:admin@example.com" in all_members


# ── GCP cost fixers ────────────────────────────────────────────────────────────

class TestGCPStopIdleInstanceFixer:
    @pytest.fixture(autouse=True)
    def fixer(self):
        from cloudctl.fixers.gcp.cost import GCPStopIdleInstanceFixer
        self.f = GCPStopIdleInstanceFixer()

    def test_can_fix_idle_gce(self):
        assert self.f.can_fix({"resource": "instances/my-vm", "issue": "idle GCE instance, CPU < 1%"})

    def test_cannot_fix_disk(self):
        assert not self.f.can_fix({"resource": "disks/disk-1", "issue": "unattached disk"})

    def test_apply_stops_instance(self):
        mock_svc = MagicMock()
        mods, _, _ = _gcp_mods(svc=mock_svc)
        with patch.dict(sys.modules, mods):
            self.f.apply(
                {"resource": "instances/my-vm", "account": "my-project"},
                {"zone": "us-central1-a"},
            )
        mock_svc.instances.return_value.stop.assert_called_once_with(
            project="my-project", zone="us-central1-a", instance="my-vm"
        )

    def test_apply_falls_back_to_region_for_zone(self):
        mock_svc = MagicMock()
        mods, _, _ = _gcp_mods(svc=mock_svc)
        with patch.dict(sys.modules, mods):
            self.f.apply(
                {"resource": "instances/my-vm", "account": "proj", "region": "europe-west1-b"},
                {},   # no zone in fix_proposal — falls back to issue["region"]
            )
        call_kwargs = mock_svc.instances.return_value.stop.call_args[1]
        assert call_kwargs["zone"] == "europe-west1-b"


class TestGCPDeleteOrphanedDiskFixer:
    @pytest.fixture(autouse=True)
    def fixer(self):
        from cloudctl.fixers.gcp.cost import GCPDeleteOrphanedDiskFixer
        self.f = GCPDeleteOrphanedDiskFixer()

    def test_can_fix_orphaned_pd(self):
        assert self.f.can_fix({"resource": "disks/my-disk", "issue": "unattached persistent disk"})

    def test_cannot_fix_instance(self):
        assert not self.f.can_fix({"resource": "instances/vm-1", "issue": "idle instance"})

    def test_apply_deletes_disk(self):
        mock_svc = MagicMock()
        mods, _, _ = _gcp_mods(svc=mock_svc)
        with patch.dict(sys.modules, mods):
            self.f.apply(
                {"resource": "disks/my-disk", "account": "my-project"},
                {"zone": "us-central1-a"},
            )
        mock_svc.disks.return_value.delete.assert_called_once_with(
            project="my-project", zone="us-central1-a", disk="my-disk"
        )


# ── Fixer registry ─────────────────────────────────────────────────────────────

class TestFixerRegistry:
    def test_get_fixer_returns_aws_sg_fixer(self):
        from cloudctl.fixers.registry import get_fixer
        fixer = get_fixer({
            "resource": "sg/sg-abc123 (default)",
            "issue": "Security group allows all inbound traffic (0.0.0.0/0)",
        })
        assert fixer is not None
        from cloudctl.fixers.aws.security import AWSOpenSecurityGroupFixer
        assert isinstance(fixer, AWSOpenSecurityGroupFixer)

    def test_get_fixer_returns_aws_s3_fixer(self):
        from cloudctl.fixers.registry import get_fixer
        fixer = get_fixer({"resource": "s3/my-bucket", "issue": "public bucket access"})
        assert fixer is not None
        from cloudctl.fixers.aws.security import AWSS3PublicAccessFixer
        assert isinstance(fixer, AWSS3PublicAccessFixer)

    def test_get_fixer_returns_none_for_unknown(self):
        from cloudctl.fixers.registry import get_fixer
        fixer = get_fixer({"resource": "unknown/resource", "issue": "unknown issue xyz123"})
        assert fixer is None

    def test_list_fixers_has_all_clouds(self):
        from cloudctl.fixers.registry import list_fixers
        fixers = list_fixers()
        clouds = {f["cloud"] for f in fixers}
        assert "aws" in clouds
        assert "azure" in clouds
        assert "gcp" in clouds
        assert len(fixers) >= 9

    def test_fixer_base_dry_run(self):
        from cloudctl.fixers.aws.security import AWSOpenSecurityGroupFixer
        f   = AWSOpenSecurityGroupFixer()
        out = f.dry_run(
            {"resource": "sg/sg-1 (default)"},
            {"steps": ["1. revoke rule"], "iac_note": "update TF"},
        )
        assert "sg/sg-1" in out
        assert "steps" in out

    def test_fixer_base_for_cloud(self):
        from cloudctl.fixers.aws.security import AWSOpenSecurityGroupFixer
        f = AWSOpenSecurityGroupFixer()
        assert f.for_cloud("aws")
        assert not f.for_cloud("azure")
