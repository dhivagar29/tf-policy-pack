package main_test

import rego.v1

untagged := {
	"resource_changes": [
		{
			"address": "aws_s3_bucket.untagged",
			"mode": "managed",
			"type": "aws_s3_bucket",
			"name": "untagged",
			"change": {"actions": ["create"], "before": null, "after": {"bucket": "u", "tags": {}}},
		},
	],
}

tagged := {
	"resource_changes": [
		{
			"address": "aws_s3_bucket.ok",
			"mode": "managed",
			"type": "aws_s3_bucket",
			"name": "ok",
			"change": {"actions": ["create"], "before": null, "after": {
				"bucket": "ok",
				"tags": {"Owner": "a", "Environment": "p", "CostCenter": "c"},
			}},
		},
		{
			"address": "aws_s3_bucket_public_access_block.ok",
			"mode": "managed",
			"type": "aws_s3_bucket_public_access_block",
			"name": "ok",
			"change": {"actions": ["create"], "before": null, "after": {
				"bucket": "ok",
				"block_public_acls": true,
				"block_public_policy": true,
				"ignore_public_acls": true,
				"restrict_public_buckets": true,
			}},
		},
		{
			"address": "aws_s3_bucket_server_side_encryption_configuration.ok",
			"mode": "managed",
			"type": "aws_s3_bucket_server_side_encryption_configuration",
			"name": "ok",
			"change": {"actions": ["create"], "before": null, "after": {"bucket": "ok"}},
		},
	],
}

test_missing_tags_warn if {
	warns := data.main.warn with input as untagged with data.required_tags as {"keys": ["Owner", "Environment", "CostCenter"]}
	ids := {w.id | some w in warns}
	"TF-TAG-001" in ids
	count(warns) == 3
}

test_tags_present_no_warn if {
	warns := data.main.warn with input as tagged with data.required_tags as {"keys": ["Owner", "Environment", "CostCenter"]}
	tag_warns := {w.id | some w in warns; w.id == "TF-TAG-001"}
	count(tag_warns) == 0
}

test_helpers_sensitive_ports if {
	22 in data.tfpolicy.helpers.sensitive_ports
	5432 in data.tfpolicy.helpers.sensitive_ports
}
