package main

import data.tfpolicy.helpers as h
import rego.v1

# TF-SG-001: aws_security_group inline ingress (sensitive ports)
deny contains msg if {
	some rc in h.resource_changes
	rc.type == "aws_security_group"
	some rule in object.get(h.after(rc), "ingress", [])
	h.sg_rule_world_sensitive(rule)
	msg := h.finding(
		"TF-SG-001",
		"high",
		rc.address,
		sprintf(
			"Security group ingress opens ports %v-%v/%v to the world",
			[object.get(rule, "from_port", "?"), object.get(rule, "to_port", "?"), object.get(rule, "protocol", "?")],
		),
	)
}

# TF-SG-001: aws_security_group inline ingress (all ports)
deny contains msg if {
	some rc in h.resource_changes
	rc.type == "aws_security_group"
	some rule in object.get(h.after(rc), "ingress", [])
	h.sg_rule_world_all_ports(rule)
	msg := h.finding(
		"TF-SG-001",
		"high",
		rc.address,
		sprintf(
			"Security group ingress opens ports %v-%v/%v to the world",
			[object.get(rule, "from_port", "?"), object.get(rule, "to_port", "?"), object.get(rule, "protocol", "?")],
		),
	)
}

# TF-SG-002: standalone ingress rules (sensitive)
deny contains msg if {
	some rc in h.resource_changes
	rc.type in {"aws_security_group_rule", "aws_vpc_security_group_ingress_rule"}
	is_ingress_rule(rc)
	rule := normalize_sg_rule(rc)
	h.sg_rule_world_sensitive(rule)
	msg := h.finding(
		"TF-SG-002",
		"high",
		rc.address,
		sprintf(
			"Security group rule opens ports %v-%v/%v to the world",
			[object.get(rule, "from_port", "?"), object.get(rule, "to_port", "?"), object.get(rule, "protocol", "?")],
		),
	)
}

# TF-SG-002: standalone ingress rules (all ports)
deny contains msg if {
	some rc in h.resource_changes
	rc.type in {"aws_security_group_rule", "aws_vpc_security_group_ingress_rule"}
	is_ingress_rule(rc)
	rule := normalize_sg_rule(rc)
	h.sg_rule_world_all_ports(rule)
	msg := h.finding(
		"TF-SG-002",
		"high",
		rc.address,
		sprintf(
			"Security group rule opens ports %v-%v/%v to the world",
			[object.get(rule, "from_port", "?"), object.get(rule, "to_port", "?"), object.get(rule, "protocol", "?")],
		),
	)
}

is_ingress_rule(rc) if {
	rc.type == "aws_vpc_security_group_ingress_rule"
}

is_ingress_rule(rc) if {
	rc.type == "aws_security_group_rule"
	object.get(h.after(rc), "type", "") == "ingress"
}

normalize_sg_rule(rc) := rule if {
	after := h.after(rc)
	rc.type == "aws_vpc_security_group_ingress_rule"
	rule := {
		"from_port": object.get(after, "from_port", 0),
		"to_port": object.get(after, "to_port", 0),
		"protocol": object.get(after, "ip_protocol", object.get(after, "protocol", "")),
		"cidr_blocks": compact_cidrs(after),
		"ipv6_cidr_blocks": compact_ipv6(after),
	}
}

normalize_sg_rule(rc) := rule if {
	after := h.after(rc)
	rc.type == "aws_security_group_rule"
	rule := {
		"from_port": object.get(after, "from_port", 0),
		"to_port": object.get(after, "to_port", 0),
		"protocol": object.get(after, "protocol", ""),
		"cidr_blocks": object.get(after, "cidr_blocks", []),
		"ipv6_cidr_blocks": object.get(after, "ipv6_cidr_blocks", []),
	}
}

compact_cidrs(after) := c if {
	v := object.get(after, "cidr_ipv4", null)
	v != null
	c := [v]
} else := object.get(after, "cidr_blocks", [])

compact_ipv6(after) := c if {
	v := object.get(after, "cidr_ipv6", null)
	v != null
	c := [v]
} else := object.get(after, "ipv6_cidr_blocks", [])
