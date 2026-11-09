package main_test

import rego.v1

bad_sg := {
	"resource_changes": [
		{
			"address": "aws_security_group.wide_open",
			"mode": "managed",
			"type": "aws_security_group",
			"name": "wide_open",
			"change": {"actions": ["create"], "before": null, "after": {
				"ingress": [
					{"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"], "ipv6_cidr_blocks": []},
				],
				"tags": {},
			}},
		},
		{
			"address": "aws_security_group_rule.db_open",
			"mode": "managed",
			"type": "aws_security_group_rule",
			"name": "db_open",
			"change": {"actions": ["create"], "before": null, "after": {
				"type": "ingress",
				"from_port": 5432,
				"to_port": 5432,
				"protocol": "tcp",
				"cidr_blocks": ["0.0.0.0/0"],
			}},
		},
		{
			"address": "aws_vpc_security_group_ingress_rule.rdp",
			"mode": "managed",
			"type": "aws_vpc_security_group_ingress_rule",
			"name": "rdp",
			"change": {"actions": ["create"], "before": null, "after": {
				"from_port": 3389,
				"to_port": 3389,
				"ip_protocol": "tcp",
				"cidr_ipv4": "0.0.0.0/0",
			}},
		},
	],
}

good_sg := {
	"resource_changes": [
		{
			"address": "aws_security_group.app",
			"mode": "managed",
			"type": "aws_security_group",
			"name": "app",
			"change": {"actions": ["create"], "before": null, "after": {
				"ingress": [
					{"from_port": 443, "to_port": 443, "protocol": "tcp", "cidr_blocks": ["10.0.0.0/8"], "ipv6_cidr_blocks": []},
				],
				"tags": {"Owner": "a", "Environment": "p", "CostCenter": "c"},
			}},
		},
	],
}

test_sg_world_open_denied if {
	denies := data.main.deny with input as bad_sg
	ids := {d.id | some d in denies}
	"TF-SG-001" in ids
	"TF-SG-002" in ids
}

test_sg_private_ok if {
	denies := data.main.deny with input as good_sg
	sg_ids := {d.id | some d in denies; startswith(d.id, "TF-SG-")}
	count(sg_ids) == 0
}
