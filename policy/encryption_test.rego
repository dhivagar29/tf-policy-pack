package main_test

import rego.v1

bad_enc := {
	"resource_changes": [
		{
			"address": "aws_s3_bucket.plain",
			"mode": "managed",
			"type": "aws_s3_bucket",
			"name": "plain",
			"change": {"actions": ["create"], "before": null, "after": {"bucket": "plain", "tags": {}}},
		},
		{
			"address": "aws_s3_bucket_public_access_block.plain",
			"mode": "managed",
			"type": "aws_s3_bucket_public_access_block",
			"name": "plain",
			"change": {"actions": ["create"], "before": null, "after": {
				"bucket": "plain",
				"block_public_acls": true,
				"block_public_policy": true,
				"ignore_public_acls": true,
				"restrict_public_buckets": true,
			}},
		},
		{
			"address": "aws_ebs_volume.plain",
			"mode": "managed",
			"type": "aws_ebs_volume",
			"name": "plain",
			"change": {"actions": ["create"], "before": null, "after": {"encrypted": false, "tags": {}}},
		},
		{
			"address": "aws_db_instance.main",
			"mode": "managed",
			"type": "aws_db_instance",
			"name": "main",
			"change": {"actions": ["create"], "before": null, "after": {"storage_encrypted": false, "tags": {}}},
		},
		{
			"address": "aws_instance.web",
			"mode": "managed",
			"type": "aws_instance",
			"name": "web",
			"change": {"actions": ["create"], "before": null, "after": {
				"root_block_device": [{"encrypted": false}],
				"ebs_block_device": [{"device_name": "/dev/sdf", "encrypted": false}],
				"tags": {},
			}},
		},
	],
}

good_enc := {
	"resource_changes": [
		{
			"address": "aws_s3_bucket.secure",
			"mode": "managed",
			"type": "aws_s3_bucket",
			"name": "secure",
			"change": {"actions": ["create"], "before": null, "after": {"bucket": "secure", "tags": {"Owner": "a", "Environment": "p", "CostCenter": "c"}}},
		},
		{
			"address": "aws_s3_bucket_public_access_block.secure",
			"mode": "managed",
			"type": "aws_s3_bucket_public_access_block",
			"name": "secure",
			"change": {"actions": ["create"], "before": null, "after": {
				"bucket": "secure",
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
			"change": {"actions": ["create"], "before": null, "after": {"bucket": "secure"}},
		},
		{
			"address": "aws_ebs_volume.data",
			"mode": "managed",
			"type": "aws_ebs_volume",
			"name": "data",
			"change": {"actions": ["create"], "before": null, "after": {"encrypted": true, "tags": {"Owner": "a", "Environment": "p", "CostCenter": "c"}}},
		},
		{
			"address": "aws_db_instance.main",
			"mode": "managed",
			"type": "aws_db_instance",
			"name": "main",
			"change": {"actions": ["create"], "before": null, "after": {"storage_encrypted": true, "tags": {"Owner": "a", "Environment": "p", "CostCenter": "c"}}},
		},
		{
			"address": "aws_instance.web",
			"mode": "managed",
			"type": "aws_instance",
			"name": "web",
			"change": {"actions": ["create"], "before": null, "after": {
				"root_block_device": [{"encrypted": true}],
				"ebs_block_device": [],
				"tags": {"Owner": "a", "Environment": "p", "CostCenter": "c"},
			}},
		},
	],
}

test_encryption_missing_denied if {
	denies := data.main.deny with input as bad_enc
	ids := {d.id | some d in denies}
	"TF-ENC-001" in ids
	"TF-ENC-002" in ids
	"TF-ENC-003" in ids
}

test_encryption_ok if {
	denies := data.main.deny with input as good_enc
	enc_ids := {d.id | some d in denies; startswith(d.id, "TF-ENC-")}
	count(enc_ids) == 0
}
