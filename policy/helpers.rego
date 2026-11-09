package tfpolicy.helpers

import rego.v1

# Resources being created or updated (not destroyed).
resource_changes contains rc if {
	some rc in input.resource_changes
	not rc.change.actions == ["delete"]
	not rc.change.actions == ["read"]
	rc.change.after != null
}

after(rc) := rc.change.after

# Prefer tags_all (includes provider default_tags). Fall back to tags only when
# tags_all is missing, null, or not an object (e.g. unknown at plan time).
tags_of(rc) := t if {
	t := object.get(after(rc), "tags_all", null)
	t != null
	is_object(t)
} else := t if {
	t := object.get(after(rc), "tags", null)
	t != null
	is_object(t)
} else := {}

same_module(a, b) if {
	object.get(a, "module_address", "") == object.get(b, "module_address", "")
}

is_cidr_open(cidr) if cidr == "0.0.0.0/0"
is_cidr_open(cidr) if cidr == "::/0"

sensitive_ports := {22, 3389, 1433, 1521, 3306, 5432, 6379, 27017, 9200, 11211}

port_in_range(port, from, to) if {
	is_number(from)
	is_number(to)
	port >= from
	port <= to
}

sg_rule_world_sensitive(rule) if {
	some cidr in object.get(rule, "cidr_blocks", [])
	is_cidr_open(cidr)
	sg_rule_covers_sensitive(rule)
}

sg_rule_world_sensitive(rule) if {
	some cidr in object.get(rule, "ipv6_cidr_blocks", [])
	is_cidr_open(cidr)
	sg_rule_covers_sensitive(rule)
}

sg_rule_covers_sensitive(rule) if {
	object.get(rule, "protocol", "") == "-1"
}

sg_rule_covers_sensitive(rule) if {
	from := to_number(object.get(rule, "from_port", -1))
	to := to_number(object.get(rule, "to_port", -1))
	some port in sensitive_ports
	port_in_range(port, from, to)
}

sg_rule_world_all_ports(rule) if {
	some cidr in object.get(rule, "cidr_blocks", [])
	is_cidr_open(cidr)
	from := to_number(object.get(rule, "from_port", -1))
	to := to_number(object.get(rule, "to_port", -1))
	from == 0
	to == 65535
}

sg_rule_world_all_ports(rule) if {
	some cidr in object.get(rule, "ipv6_cidr_blocks", [])
	is_cidr_open(cidr)
	from := to_number(object.get(rule, "from_port", -1))
	to := to_number(object.get(rule, "to_port", -1))
	from == 0
	to == 65535
}

finding(id, severity, resource, message) := {
	"id": id,
	"severity": severity,
	"resource": resource,
	"msg": sprintf("[%s] (%s) %s: %s", [id, severity, resource, message]),
}
