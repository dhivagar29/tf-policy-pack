package main

import data.tfpolicy.helpers as h
import rego.v1

# TF-ENC-001: S3 bucket without explicit server-side encryption configuration.
# AWS has encrypted new buckets with SSE-S3 by default since January 2023, so
# a missing config is a warn (ask for an explicit SSE block), not a high deny.
warn contains msg if {
	some rc in h.resource_changes
	rc.type == "aws_s3_bucket"
	not bucket_has_sse(rc)
	# Legacy: server_side_encryption_configuration on the bucket itself
	not legacy_bucket_sse(rc)
	msg := h.finding(
		"TF-ENC-001",
		"low",
		rc.address,
		"S3 bucket has no explicit server-side encryption configuration in this plan (SSE-S3 is the AWS default since January 2023; declare SSE explicitly)",
	)
}

# TF-ENC-002: EBS volume / EC2 root or ebs block device without encryption
# (aws_launch_template block devices are not covered — see README Limits)
deny contains msg if {
	some rc in h.resource_changes
	rc.type == "aws_ebs_volume"
	enc := object.get(h.after(rc), "encrypted", false)
	enc != true
	msg := h.finding(
		"TF-ENC-002",
		"high",
		rc.address,
		"EBS volume is not encrypted",
	)
}

deny contains msg if {
	some rc in h.resource_changes
	rc.type == "aws_instance"
	some bd in object.get(h.after(rc), "ebs_block_device", [])
	object.get(bd, "encrypted", false) != true
	msg := h.finding(
		"TF-ENC-002",
		"high",
		rc.address,
		sprintf("EC2 ebs_block_device %v is not encrypted", [object.get(bd, "device_name", "?")]),
	)
}

deny contains msg if {
	some rc in h.resource_changes
	rc.type == "aws_instance"
	root := object.get(h.after(rc), "root_block_device", null)
	is_array(root)
	some bd in root
	object.get(bd, "encrypted", false) != true
	msg := h.finding(
		"TF-ENC-002",
		"high",
		rc.address,
		"EC2 root_block_device is not encrypted",
	)
}

deny contains msg if {
	some rc in h.resource_changes
	rc.type == "aws_instance"
	root := object.get(h.after(rc), "root_block_device", null)
	is_object(root)
	object.get(root, "encrypted", false) != true
	msg := h.finding(
		"TF-ENC-002",
		"high",
		rc.address,
		"EC2 root_block_device is not encrypted",
	)
}

# TF-ENC-003: RDS instance / cluster without storage_encrypted
deny contains msg if {
	some rc in h.resource_changes
	rc.type in {"aws_db_instance", "aws_rds_cluster"}
	object.get(h.after(rc), "storage_encrypted", false) != true
	msg := h.finding(
		"TF-ENC-003",
		"high",
		rc.address,
		"RDS storage_encrypted is not true",
	)
}

bucket_has_sse(bucket_rc) if {
	some sse in h.resource_changes
	sse.type == "aws_s3_bucket_server_side_encryption_configuration"
	sse.name == bucket_rc.name
	h.same_module(sse, bucket_rc)
}

bucket_has_sse(bucket_rc) if {
	some sse in h.resource_changes
	sse.type == "aws_s3_bucket_server_side_encryption_configuration"
	h.same_module(sse, bucket_rc)
	ref := object.get(h.after(sse), "bucket", "")
	ref != ""
	ref == object.get(h.after(bucket_rc), "bucket", "")
}

legacy_bucket_sse(rc) if {
	cfg := object.get(h.after(rc), "server_side_encryption_configuration", null)
	cfg != null
	count(cfg) > 0
}
