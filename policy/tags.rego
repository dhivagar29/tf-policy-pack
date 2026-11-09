package main

import data.tfpolicy.helpers as h
import rego.v1

# Default required tags when data file is absent.
default required_tag_keys := ["Owner", "Environment", "CostCenter"]

required_tag_keys := data.required_tags.keys if {
	data.required_tags.keys
}

# Resource types that must carry tags.
taggable_types := {
	"aws_s3_bucket",
	"aws_instance",
	"aws_ebs_volume",
	"aws_db_instance",
	"aws_rds_cluster",
	"aws_security_group",
	"aws_subnet",
	"aws_vpc",
	"aws_ecs_service",
	"aws_ecs_cluster",
	"aws_lambda_function",
	"aws_kms_key",
}

# TF-TAG-001: missing required tag (warn / low)
warn contains msg if {
	some rc in h.resource_changes
	rc.type in taggable_types
	tags := h.tags_of(rc)
	some key in required_tag_keys
	not tag_present(tags, key)
	msg := h.finding(
		"TF-TAG-001",
		"low",
		rc.address,
		sprintf("Missing required tag %q", [key]),
	)
}

tag_present(tags, key) if {
	tags[key]
	tags[key] != ""
}

# Case-insensitive fallback for common drift in tag key casing
tag_present(tags, key) if {
	some k, v in tags
	lower(k) == lower(key)
	v != ""
}
