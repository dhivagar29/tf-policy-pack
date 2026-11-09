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
