package cloudctl.lib

import rego.v1

# Helpers shared by the built-in rules (rules.yaml) and by user rule packs.
# Everything here is pure: no network, no clock.

# ── actions ──────────────────────────────────────────────────────────────────

mutating(change) if change.action in {"create", "update", "replace"}

destroying(change) if change.action in {"delete", "replace"}

known(v) if {
	v != null
	v != "(known after apply)"
}

as_list(x) := x if is_array(x)

as_list(x) := [x] if not is_array(x)

# The resource's attributes: planned values, or the prior state for deletes.
attrs(change) := change.after if is_object(change.after)

attrs(change) := change.before if {
	not is_object(change.after)
	is_object(change.before)
}

attrs(change) := {} if {
	not is_object(change.after)
	not is_object(change.before)
}

# ── stateful resources (data loss if destroyed) ──────────────────────────────

stateful_types := {
	# AWS — Terraform
	"aws_db_instance", "aws_rds_cluster", "aws_rds_cluster_instance", "aws_dynamodb_table",
	"aws_s3_bucket", "aws_ebs_volume", "aws_ebs_snapshot", "aws_efs_file_system",
	"aws_elasticache_cluster", "aws_elasticache_replication_group", "aws_kms_key",
	"aws_redshift_cluster", "aws_docdb_cluster", "aws_neptune_cluster", "aws_opensearch_domain",
	"aws_elasticsearch_domain", "aws_msk_cluster", "aws_kinesis_stream", "aws_sqs_queue",
	"aws_secretsmanager_secret", "aws_backup_vault", "aws_fsx_lustre_file_system",
	# AWS — CloudFormation / CDK
	"AWS::RDS::DBInstance", "AWS::RDS::DBCluster", "AWS::DynamoDB::Table", "AWS::DynamoDB::GlobalTable",
	"AWS::S3::Bucket", "AWS::EC2::Volume", "AWS::EFS::FileSystem", "AWS::ElastiCache::CacheCluster",
	"AWS::ElastiCache::ReplicationGroup", "AWS::KMS::Key", "AWS::Redshift::Cluster",
	"AWS::DocDB::DBCluster", "AWS::OpenSearchService::Domain", "AWS::MSK::Cluster",
	"AWS::Kinesis::Stream", "AWS::SQS::Queue", "AWS::SecretsManager::Secret", "AWS::Backup::BackupVault",
	# Azure — Terraform
	"azurerm_storage_account", "azurerm_mssql_database", "azurerm_mssql_server",
	"azurerm_postgresql_flexible_server", "azurerm_postgresql_server", "azurerm_mysql_flexible_server",
	"azurerm_cosmosdb_account", "azurerm_key_vault", "azurerm_key_vault_key", "azurerm_managed_disk",
	"azurerm_redis_cache", "azurerm_servicebus_namespace", "azurerm_eventhub_namespace",
	"azurerm_recovery_services_vault", "azurerm_data_factory", "azurerm_synapse_workspace",
	# Azure — ARM / Bicep
	"Microsoft.Storage/storageAccounts", "Microsoft.Sql/servers", "Microsoft.Sql/servers/databases",
	"Microsoft.DBforPostgreSQL/flexibleServers", "Microsoft.DBforMySQL/flexibleServers",
	"Microsoft.DocumentDB/databaseAccounts", "Microsoft.KeyVault/vaults", "Microsoft.Compute/disks",
	"Microsoft.Cache/redis", "Microsoft.ServiceBus/namespaces", "Microsoft.EventHub/namespaces",
	"Microsoft.RecoveryServices/vaults",
	# GCP — Terraform
	"google_sql_database_instance", "google_sql_database", "google_storage_bucket",
	"google_bigquery_dataset", "google_bigquery_table", "google_compute_disk", "google_kms_crypto_key",
	"google_kms_key_ring", "google_spanner_instance", "google_spanner_database",
	"google_bigtable_instance", "google_firestore_database", "google_redis_instance",
	"google_filestore_instance", "google_pubsub_topic", "google_secret_manager_secret",
	# Pulumi type tokens (most common)
	"aws:s3/bucket:Bucket", "aws:s3/bucketV2:BucketV2", "aws:rds/instance:Instance",
	"aws:rds/cluster:Cluster", "aws:dynamodb/table:Table", "aws:ebs/volume:Volume",
	"azure-native:storage:StorageAccount", "azure-native:sql:Database",
	"azure-native:keyvault:Vault", "gcp:storage/bucket:Bucket", "gcp:sql/databaseInstance:DatabaseInstance",
	"gcp:bigquery/dataset:Dataset",
}

is_stateful(change) if change.type in stateful_types

is_stateful(change) if {
	change.cloud == "kubernetes"
	some kind in {"/PersistentVolumeClaim", "/PersistentVolume", "/Namespace", "/StatefulSet"}
	endswith(change.type, kind)
}

# ── network exposure ─────────────────────────────────────────────────────────

public_sources := {"0.0.0.0/0", "::/0", "*", "internet", "any"}

is_public(src) if lower(src) in public_sources

safe_port(p) if to_number(p) in {80, 443}

aws_range_unsafe(r) if not r.from_port == r.to_port

aws_range_unsafe(r) if {
	r.from_port == r.to_port
	not safe_port(r.from_port)
}

# AWS: inline ingress blocks on aws_security_group
open_ingress(change) if {
	change.type == "aws_security_group"
	some r in as_list(object.get(change.after, "ingress", []))
	some c in array.concat(as_list(object.get(r, "cidr_blocks", [])), as_list(object.get(r, "ipv6_cidr_blocks", [])))
	is_public(c)
	aws_range_unsafe(r)
}

# AWS: aws_security_group_rule
open_ingress(change) if {
	change.type == "aws_security_group_rule"
	change.after.type == "ingress"
	some c in array.concat(as_list(object.get(change.after, "cidr_blocks", [])), as_list(object.get(change.after, "ipv6_cidr_blocks", [])))
	is_public(c)
	aws_range_unsafe(change.after)
}

# AWS: aws_vpc_security_group_ingress_rule
open_ingress(change) if {
	change.type == "aws_vpc_security_group_ingress_rule"
	some c in [object.get(change.after, "cidr_ipv4", ""), object.get(change.after, "cidr_ipv6", "")]
	is_string(c)
	is_public(c)
	aws_range_unsafe(change.after)
}

azure_rule_open(r) if {
	lower(object.get(r, "direction", "")) == "inbound"
	lower(object.get(r, "access", "")) == "allow"
	srcs := array.concat(as_list(object.get(r, "source_address_prefix", "")), as_list(object.get(r, "source_address_prefixes", [])))
	some s in srcs
	is_string(s)
	is_public(s)
	ports := array.concat(as_list(object.get(r, "destination_port_range", "")), as_list(object.get(r, "destination_port_ranges", [])))
	some p in ports
	is_string(p)
	p != ""
	not p in {"80", "443"}
}

# Azure: azurerm_network_security_rule
open_ingress(change) if {
	change.type == "azurerm_network_security_rule"
	azure_rule_open(change.after)
}

# Azure: inline rules on azurerm_network_security_group
open_ingress(change) if {
	change.type == "azurerm_network_security_group"
	some r in as_list(object.get(change.after, "security_rule", []))
	azure_rule_open(r)
}

# Azure ARM / Bicep: Microsoft.Network/networkSecurityGroups/securityRules
open_ingress(change) if {
	change.type == "Microsoft.Network/networkSecurityGroups/securityRules"
	p := object.get(change.after, "properties", {})
	azure_rule_open({
		"direction": object.get(p, "direction", ""), "access": object.get(p, "access", ""),
		"source_address_prefix": object.get(p, "sourceAddressPrefix", ""),
		"source_address_prefixes": object.get(p, "sourceAddressPrefixes", []),
		"destination_port_range": object.get(p, "destinationPortRange", ""),
		"destination_port_ranges": object.get(p, "destinationPortRanges", []),
	})
}

gcp_allow_unsafe(a) if count(as_list(object.get(a, "ports", []))) == 0

gcp_allow_unsafe(a) if {
	some p in as_list(object.get(a, "ports", []))
	not p in {"80", "443"}
}

# GCP: google_compute_firewall (direction defaults to INGRESS)
open_ingress(change) if {
	change.type == "google_compute_firewall"
	upper(object.get(change.after, "direction", "INGRESS")) == "INGRESS"
	some s in as_list(object.get(change.after, "source_ranges", []))
	is_public(s)
	some a in as_list(object.get(change.after, "allow", []))
	gcp_allow_unsafe(a)
}

# ── IAM ──────────────────────────────────────────────────────────────────────

aws_policy_types := {
	"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy",
	"aws_iam_policy_document",
}

aws_resource_policy_types := {
	"aws_s3_bucket_policy", "aws_sqs_queue_policy", "aws_sns_topic_policy", "aws_kms_key",
	"aws_ecr_repository_policy", "aws_lambda_permission", "aws_secretsmanager_secret_policy",
}

policy_doc(v) := json.unmarshal(v) if {
	is_string(v)
	startswith(trim_space(v), "{")
}

policy_doc(v) := v if is_object(v)

statements(doc) := doc.Statement if is_array(doc.Statement)

statements(doc) := [doc.Statement] if is_object(doc.Statement)

aws_admin_statement(st) if {
	st.Effect == "Allow"
	some a in as_list(object.get(st, "Action", []))
	a in {"*", "*:*"}
	some r in as_list(object.get(st, "Resource", []))
	r == "*"
}

admin_grant(change) if {
	change.type in aws_policy_types
	doc := policy_doc(object.get(change.after, "policy", object.get(change.after, "json", "")))
	some st in statements(doc)
	aws_admin_statement(st)
}

admin_grant(change) if {
	change.type == "azurerm_role_assignment"
	object.get(change.after, "role_definition_name", "") in {"Owner", "Contributor", "User Access Administrator"}
	regex.match(`^/subscriptions/[^/]+/?$`, object.get(change.after, "scope", ""))
}

admin_grant(change) if {
	startswith(change.type, "google_")
	contains(change.type, "_iam_")
	some kind in {"google_project_", "google_organization_", "google_folder_"}
	startswith(change.type, kind)
	object.get(change.after, "role", "") in {"roles/owner", "roles/editor"}
}

public_members := {"allUsers", "allAuthenticatedUsers"}

public_principal(change) if {
	startswith(change.type, "google_")
	contains(change.type, "_iam_member")
	object.get(change.after, "member", "") in public_members
}

public_principal(change) if {
	startswith(change.type, "google_")
	contains(change.type, "_iam_binding")
	some m in as_list(object.get(change.after, "members", []))
	m in public_members
}

aws_public_statement(st) if {
	st.Effect == "Allow"
	p := object.get(st, "Principal", "")
	aws_star_principal(p)
	not st.Condition
}

aws_star_principal(p) if p == "*"

aws_star_principal(p) if {
	is_object(p)
	some v in as_list(object.get(p, "AWS", []))
	v == "*"
}

public_principal(change) if {
	change.type in aws_resource_policy_types
	doc := policy_doc(object.get(change.after, "policy", ""))
	some st in statements(doc)
	aws_public_statement(st)
}

public_principal(change) if {
	change.type == "aws_lambda_permission"
	object.get(change.after, "principal", "") == "*"
}

public_principal(change) if {
	change.type == "azurerm_storage_container"
	object.get(change.after, "container_access_type", "private") in {"blob", "container"}
}

# ── storage exposure / encryption ────────────────────────────────────────────

public_storage(change) if {
	change.type == "aws_s3_bucket_public_access_block"
	some k in ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"]
	object.get(change.after, k, true) == false
}

public_storage(change) if {
	change.type == "aws_s3_bucket_acl"
	object.get(change.after, "acl", "") in {"public-read", "public-read-write", "authenticated-read"}
}

public_storage(change) if {
	change.type == "azurerm_storage_account"
	object.get(change.after, "allow_nested_items_to_be_public", false) == true
}

public_storage(change) if {
	change.type == "Microsoft.Storage/storageAccounts"
	object.get(object.get(change.after, "properties", {}), "allowBlobPublicAccess", false) == true
}

public_storage(change) if {
	change.type == "google_storage_bucket"
	object.get(change.after, "public_access_prevention", "") == "inherited"
	object.get(change.after, "uniform_bucket_level_access", true) == false
}

weak_encryption(change) if {
	change.type in {"aws_db_instance", "aws_rds_cluster", "aws_docdb_cluster", "aws_neptune_cluster"}
	object.get(change.after, "storage_encrypted", true) == false
}

weak_encryption(change) if {
	change.type == "aws_ebs_volume"
	object.get(change.after, "encrypted", true) == false
}

weak_encryption(change) if {
	change.type == "azurerm_storage_account"
	object.get(change.after, "min_tls_version", "TLS1_2") in {"TLS1_0", "TLS1_1"}
}

weak_encryption(change) if {
	change.type == "azurerm_storage_account"
	object.get(change.after, "https_traffic_only_enabled", true) == false
}

weak_encryption(change) if {
	change.type == "google_sql_database_instance"
	some s in as_list(object.get(change.after, "settings", []))
	some ip in as_list(object.get(s, "ip_configuration", []))
	object.get(ip, "ssl_mode", "") == "ALLOW_UNENCRYPTED_AND_ENCRYPTED"
}

# ── scope ────────────────────────────────────────────────────────────────────

# concat, not sprintf: rego-cpp's sprintf quotes %s string arguments.
azure_scope_prefix := concat("", [
	"/subscriptions/", lower(input.environment.scope.subscription_id),
	"/resourcegroups/", lower(input.environment.scope.resource_group),
])

out_of_scope(change) if {
	input.environment.cloud == "azure"
	change.cloud == "azure"
	startswith(lower(change.address), "/subscriptions/")
	addr := lower(change.address)
	addr != azure_scope_prefix
	not startswith(addr, concat("", [azure_scope_prefix, "/"]))
}

out_of_scope(change) if {
	input.environment.cloud == "azure"
	change.cloud == "azure"
	rg := object.get(attrs(change), "resource_group_name", null)
	known(rg)
	is_string(rg)
	lower(rg) != lower(input.environment.scope.resource_group)
}

out_of_scope(change) if {
	input.environment.cloud == "gcp"
	change.cloud == "gcp"
	p := object.get(attrs(change), "project", null)
	known(p)
	is_string(p)
	p != input.environment.scope.project_id
}

out_of_scope(change) if {
	input.environment.cloud == "aws"
	change.cloud == "aws"
	region := object.get(attrs(change), "region", null)
	known(region)
	is_string(region)
	region != input.environment.scope.region
	region != ""
}
