package main_test

import rego.v1

bad := {
	"format_version": "1.2",
	"resource_changes": [
		{
			"address": "aws_s3_bucket.public",
			"mode": "managed",
			"type": "aws_s3_bucket",
			"name": "public",
			"change": {"actions": ["create"], "before": null, "after": {"bucket": "demo-public-logs", "acl": "public-read", "tags": {}}},
		},
		{
			"address": "aws_s3_bucket_acl.public",
			"mode": "managed",
			"type": "aws_s3_bucket_acl",
			"name": "public",
			"change": {"actions": ["create"], "before": null, "after": {"bucket": "demo-public-logs", "acl": "public-read-write"}},
		},
		{
			"address": "aws_s3_bucket_public_access_block.weak",
			"mode": "managed",
			"type": "aws_s3_bucket_public_access_block",
			"name": "weak",
			"change": {"actions": ["create"], "before": null, "after": {
				"bucket": "other",
				"block_public_acls": false,
				"block_public_policy": true,
				"ignore_public_acls": false,
				"restrict_public_buckets": true,
			}},
		},
	],
}

good := {
	"format_version": "1.2",
	"resource_changes": [
		{
			"address": "aws_s3_bucket.secure",
			"mode": "managed",
			"type": "aws_s3_bucket",
			"name": "secure",
			"change": {"actions": ["create"], "before": null, "after": {"bucket": "demo-secure", "tags": {"Owner": "a", "Environment": "p", "CostCenter": "c"}}},
		},
		{
			"address": "aws_s3_bucket_public_access_block.secure",
			"mode": "managed",
			"type": "aws_s3_bucket_public_access_block",
			"name": "secure",
			"change": {"actions": ["create"], "before": null, "after": {
				"bucket": "demo-secure",
				"block_public_acls": true,
				"block_public_policy": true,
				"ignore_public_acls": true,
				"restrict_public_buckets": true,
			}},
		},
		{
			"address": "aws_s3_bucket_server_side_encryption_configuration.secure",
			"mode": "managed",
			"type": "aws_s3_bucket_server_side_encryption_configuration",
			"name": "secure",
			"change": {"actions": ["create"], "before": null, "after": {"bucket": "demo-secure"}},
		},
	],
}

auth_read := {
	"format_version": "1.2",
	"resource_changes": [
		{
			"address": "aws_s3_bucket.auth",
			"mode": "managed",
			"type": "aws_s3_bucket",
			"name": "auth",
			"change": {"actions": ["create"], "before": null, "after": {"bucket": "demo-auth", "acl": "authenticated-read", "tags": {}}},
		},
		{
			"address": "aws_s3_bucket_acl.auth",
			"mode": "managed",
			"type": "aws_s3_bucket_acl",
			"name": "auth",
			"change": {"actions": ["create"], "before": null, "after": {"bucket": "demo-auth", "acl": "authenticated-read"}},
		},
	],
}

# module.a bucket "logs" must NOT be satisfied by module.b's public_access_block "logs"
cross_module := {
	"format_version": "1.2",
	"resource_changes": [
		{
			"address": "module.a.aws_s3_bucket.logs",
			"module_address": "module.a",
			"mode": "managed",
			"type": "aws_s3_bucket",
			"name": "logs",
			"change": {"actions": ["create"], "before": null, "after": {"bucket": "module-a-logs", "tags": {}}},
		},
		{
			"address": "module.b.aws_s3_bucket.logs",
			"module_address": "module.b",
			"mode": "managed",
			"type": "aws_s3_bucket",
			"name": "logs",
			"change": {"actions": ["create"], "before": null, "after": {"bucket": "module-b-logs", "tags": {}}},
		},
		{
			"address": "module.b.aws_s3_bucket_public_access_block.logs",
			"module_address": "module.b",
			"mode": "managed",
			"type": "aws_s3_bucket_public_access_block",
			"name": "logs",
			"change": {"actions": ["create"], "before": null, "after": {
				"bucket": "module-b-logs",
				"block_public_acls": true,
				"block_public_policy": true,
				"ignore_public_acls": true,
				"restrict_public_buckets": true,
			}},
		},
		{
			"address": "module.b.aws_s3_bucket_server_side_encryption_configuration.logs",
			"module_address": "module.b",
			"mode": "managed",
			"type": "aws_s3_bucket_server_side_encryption_configuration",
			"name": "logs",
			"change": {"actions": ["create"], "before": null, "after": {"bucket": "module-b-logs"}},
		},
	],
}

test_s3_public_acl_denied if {
	denies := data.main.deny with input as bad
	ids := {d.id | some d in denies}
	"TF-S3-001" in ids
	"TF-S3-002" in ids
	"TF-S3-003" in ids
	"TF-S3-004" in ids
}

test_s3_secure_no_deny if {
	denies := data.main.deny with input as good
	s3_ids := {d.id | some d in denies; startswith(d.id, "TF-S3-")}
	count(s3_ids) == 0
}

test_authenticated_read_denied if {
	denies := data.main.deny with input as auth_read
	ids := {d.id | some d in denies}
	"TF-S3-001" in ids
	"TF-S3-002" in ids
}

test_cross_module_pab_does_not_match if {
	denies := data.main.deny with input as cross_module
	warns := data.main.warn with input as cross_module
	# module.a bucket has no same-module PAB → TF-S3-003
	s3_003 := {d.resource | some d in denies; d.id == "TF-S3-003"}
	"module.a.aws_s3_bucket.logs" in s3_003
	# module.b bucket has matching PAB → no TF-S3-003
	not "module.b.aws_s3_bucket.logs" in s3_003
	# module.a also gets TF-ENC-001 warn (no same-module SSE); module.b does not
	enc_warn := {w.resource | some w in warns; w.id == "TF-ENC-001"}
	"module.a.aws_s3_bucket.logs" in enc_warn
	not "module.b.aws_s3_bucket.logs" in enc_warn
}
