package main

import data.tfpolicy.helpers as h
import rego.v1

# TF-S3-001: bucket ACL grants public read/write
deny contains msg if {
	some rc in h.resource_changes
	rc.type == "aws_s3_bucket"
	acl := object.get(h.after(rc), "acl", "")
	acl in {"public-read", "public-read-write"}
	msg := h.finding(
		"TF-S3-001",
		"high",
		rc.address,
		sprintf("S3 bucket ACL %q grants public access", [acl]),
	)
}

# TF-S3-002: aws_s3_bucket_acl with public ACL
deny contains msg if {
	some rc in h.resource_changes
	rc.type == "aws_s3_bucket_acl"
	acl := object.get(h.after(rc), "acl", "")
	acl in {"public-read", "public-read-write"}
	msg := h.finding(
		"TF-S3-002",
		"high",
		rc.address,
		sprintf("S3 bucket ACL resource uses %q", [acl]),
	)
}

# TF-S3-003: public_access_block missing for a planned bucket (same module address prefix)
deny contains msg if {
	some rc in h.resource_changes
	rc.type == "aws_s3_bucket"
	not bucket_has_public_access_block(rc)
	msg := h.finding(
		"TF-S3-003",
		"high",
		rc.address,
		"S3 bucket has no aws_s3_bucket_public_access_block in this plan",
	)
}

# TF-S3-004: public_access_block present but one or more flags disabled
deny contains msg if {
	some rc in h.resource_changes
	rc.type == "aws_s3_bucket_public_access_block"
	after := h.after(rc)
	not after.block_public_acls
	msg := h.finding(
		"TF-S3-004",
		"high",
		rc.address,
		"block_public_acls is disabled",
	)
}

deny contains msg if {
	some rc in h.resource_changes
	rc.type == "aws_s3_bucket_public_access_block"
	after := h.after(rc)
	not after.block_public_policy
	msg := h.finding(
		"TF-S3-004",
		"high",
		rc.address,
		"block_public_policy is disabled",
	)
}

deny contains msg if {
	some rc in h.resource_changes
	rc.type == "aws_s3_bucket_public_access_block"
	after := h.after(rc)
	not after.ignore_public_acls
	msg := h.finding(
		"TF-S3-004",
		"high",
		rc.address,
		"ignore_public_acls is disabled",
	)
}

deny contains msg if {
	some rc in h.resource_changes
	rc.type == "aws_s3_bucket_public_access_block"
	after := h.after(rc)
	not after.restrict_public_buckets
	msg := h.finding(
		"TF-S3-004",
		"high",
		rc.address,
		"restrict_public_buckets is disabled",
	)
}

bucket_has_public_access_block(bucket_rc) if {
	some pab in h.resource_changes
	pab.type == "aws_s3_bucket_public_access_block"
	# Match by explicit bucket attribute equaling the bucket id/name, or shared name stem
	bucket_ref := object.get(h.after(pab), "bucket", "")
	bucket_ref != ""
	bucket_matches(bucket_rc, bucket_ref)
}

bucket_has_public_access_block(bucket_rc) if {
	some pab in h.resource_changes
	pab.type == "aws_s3_bucket_public_access_block"
	# Fallback: same Terraform resource name (common pattern: aws_s3_bucket.foo + public_access_block.foo)
	pab.name == bucket_rc.name
}

bucket_matches(bucket_rc, ref) if {
	ref == object.get(h.after(bucket_rc), "bucket", "")
}

bucket_matches(bucket_rc, ref) if {
	ref == object.get(h.after(bucket_rc), "id", "")
}

bucket_matches(bucket_rc, ref) if {
	ref == bucket_rc.address
}

bucket_matches(bucket_rc, ref) if {
	ref == sprintf("%s.%s", [bucket_rc.type, bucket_rc.name])
}
