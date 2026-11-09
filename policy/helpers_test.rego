package tfpolicy.helpers_test

import data.tfpolicy.helpers as h
import rego.v1

test_is_cidr_open if {
	h.is_cidr_open("0.0.0.0/0")
	h.is_cidr_open("::/0")
	not h.is_cidr_open("10.0.0.0/8")
}

test_finding_shape if {
	f := h.finding("TF-X", "high", "aws_s3_bucket.x", "hello")
	f.id == "TF-X"
	f.severity == "high"
	f.resource == "aws_s3_bucket.x"
	contains(f.msg, "TF-X")
}

test_sg_all_ports if {
	h.sg_rule_world_all_ports({"from_port": 0, "to_port": 65535, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"], "ipv6_cidr_blocks": []})
}
