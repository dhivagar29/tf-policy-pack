/**
 * Faithful client-side port of the Rego policies in ../policy.
 * Kept in sync by scripts/sync-check.cjs (compares against opa eval on fixtures).
 */
(function (root, factory) {
  var api = factory();
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  }
  if (root) {
    root.TfPolicyPack = api;
  }
  return api;
})(typeof globalThis !== "undefined" ? globalThis : typeof self !== "undefined" ? self : undefined, function () {
  "use strict";

  var SENSITIVE_PORTS = [22, 3389, 1433, 1521, 3306, 5432, 6379, 27017, 9200, 11211];
  var DEFAULT_TAGS = ["Owner", "Environment", "CostCenter"];
  var PUBLIC_ACLS = { "public-read": 1, "public-read-write": 1, "authenticated-read": 1 };
  var TAGGABLE = {
    aws_s3_bucket: 1,
    aws_instance: 1,
    aws_ebs_volume: 1,
    aws_db_instance: 1,
    aws_rds_cluster: 1,
    aws_security_group: 1,
    aws_subnet: 1,
    aws_vpc: 1,
    aws_ecs_service: 1,
    aws_ecs_cluster: 1,
    aws_lambda_function: 1,
    aws_kms_key: 1,
  };

  function finding(id, severity, resource, message) {
    return {
      id: id,
      severity: severity,
      resource: resource,
      msg: "[" + id + "] (" + severity + ") " + resource + ": " + message,
    };
  }

  function resourceChanges(input) {
    var list = (input && input.resource_changes) || [];
    var out = [];
    for (var i = 0; i < list.length; i++) {
      var rc = list[i];
      var actions = (rc.change && rc.change.actions) || [];
      if (actions.length === 1 && (actions[0] === "delete" || actions[0] === "read")) continue;
      if (!rc.change || rc.change.after == null) continue;
      out.push(rc);
    }
    return out;
  }

  function after(rc) {
    return rc.change.after;
  }

  function moduleAddress(rc) {
    return rc.module_address != null ? String(rc.module_address) : "";
  }

  function sameModule(a, b) {
    return moduleAddress(a) === moduleAddress(b);
  }

  // Prefer tags_all (includes provider default_tags). Fall back to tags only when
  // tags_all is missing, null, or not a plain object.
  function tagsOf(rc) {
    var a = after(rc);
    if (a.tags_all != null && typeof a.tags_all === "object" && !Array.isArray(a.tags_all)) return a.tags_all;
    if (a.tags != null && typeof a.tags === "object" && !Array.isArray(a.tags)) return a.tags;
    return {};
  }

  function isCidrOpen(cidr) {
    return cidr === "0.0.0.0/0" || cidr === "::/0";
  }

  function portInRange(port, from, to) {
    return typeof from === "number" && typeof to === "number" && port >= from && port <= to;
  }

  function sgCoversSensitive(rule) {
    var proto = rule.protocol != null ? String(rule.protocol) : "";
    if (proto === "-1") return true;
    var from = Number(rule.from_port);
    var to = Number(rule.to_port);
    for (var i = 0; i < SENSITIVE_PORTS.length; i++) {
      if (portInRange(SENSITIVE_PORTS[i], from, to)) return true;
    }
    return false;
  }

  function sgWorldSensitive(rule) {
    var blocks = [].concat(rule.cidr_blocks || [], rule.ipv6_cidr_blocks || []);
    for (var i = 0; i < blocks.length; i++) {
      if (isCidrOpen(blocks[i]) && sgCoversSensitive(rule)) return true;
    }
    return false;
  }

  function sgWorldAllPorts(rule) {
    var blocks = [].concat(rule.cidr_blocks || [], rule.ipv6_cidr_blocks || []);
    var from = Number(rule.from_port);
    var to = Number(rule.to_port);
    if (!(from === 0 && to === 65535)) return false;
    for (var i = 0; i < blocks.length; i++) {
      if (isCidrOpen(blocks[i])) return true;
    }
    return false;
  }

  function bucketMatches(bucketRc, ref) {
    var a = after(bucketRc);
    return ref === a.bucket || ref === a.id || ref === bucketRc.type + "." + bucketRc.name;
  }

  function hasPublicAccessBlock(rcs, bucketRc) {
    for (var i = 0; i < rcs.length; i++) {
      var pab = rcs[i];
      if (pab.type !== "aws_s3_bucket_public_access_block") continue;
      if (!sameModule(pab, bucketRc)) continue;
      if (pab.name === bucketRc.name) return true;
      var ref = after(pab).bucket || "";
      if (ref && bucketMatches(bucketRc, ref)) return true;
    }
    return false;
  }

  function hasSSE(rcs, bucketRc) {
    var a = after(bucketRc);
    if (a.server_side_encryption_configuration && a.server_side_encryption_configuration.length) return true;
    for (var i = 0; i < rcs.length; i++) {
      var sse = rcs[i];
      if (sse.type !== "aws_s3_bucket_server_side_encryption_configuration") continue;
      if (!sameModule(sse, bucketRc)) continue;
      if (sse.name === bucketRc.name) return true;
      var ref = after(sse).bucket || "";
      if (ref && ref === a.bucket) return true;
    }
    return false;
  }

  function normalizeSgRule(rc) {
    var a = after(rc);
    if (rc.type === "aws_vpc_security_group_ingress_rule") {
      return {
        from_port: a.from_port || 0,
        to_port: a.to_port || 0,
        protocol: a.ip_protocol != null ? a.ip_protocol : a.protocol || "",
        cidr_blocks: a.cidr_ipv4 != null ? [a.cidr_ipv4] : a.cidr_blocks || [],
        ipv6_cidr_blocks: a.cidr_ipv6 != null ? [a.cidr_ipv6] : a.ipv6_cidr_blocks || [],
      };
    }
    return {
      from_port: a.from_port || 0,
      to_port: a.to_port || 0,
      protocol: a.protocol || "",
      cidr_blocks: a.cidr_blocks || [],
      ipv6_cidr_blocks: a.ipv6_cidr_blocks || [],
    };
  }

  function isIngressRule(rc) {
    if (rc.type === "aws_vpc_security_group_ingress_rule") return true;
    if (rc.type === "aws_security_group_rule" && after(rc).type === "ingress") return true;
    return false;
  }

  function tagPresent(tags, key) {
    if (tags[key] != null && tags[key] !== "") return true;
    var lower = String(key).toLowerCase();
    for (var k in tags) {
      if (Object.prototype.hasOwnProperty.call(tags, k) && String(k).toLowerCase() === lower && tags[k] !== "") {
        return true;
      }
    }
    return false;
  }

  function evaluate(input, options) {
    options = options || {};
    var requiredTags = options.requiredTags || DEFAULT_TAGS;
    var rcs = resourceChanges(input);
    var deny = [];
    var warn = [];
    var i, rc, a, rule, j, flags;

    for (i = 0; i < rcs.length; i++) {
      rc = rcs[i];
      a = after(rc);

      if (rc.type === "aws_s3_bucket") {
        if (PUBLIC_ACLS[a.acl]) {
          deny.push(finding("TF-S3-001", "high", rc.address, 'S3 bucket ACL "' + a.acl + '" grants public access'));
        }
        if (!hasPublicAccessBlock(rcs, rc)) {
          deny.push(
            finding("TF-S3-003", "high", rc.address, "S3 bucket has no aws_s3_bucket_public_access_block in this plan")
          );
        }
        if (!hasSSE(rcs, rc)) {
          warn.push(
            finding(
              "TF-ENC-001",
              "low",
              rc.address,
              "S3 bucket has no explicit server-side encryption configuration in this plan (SSE-S3 is the AWS default since January 2023; declare SSE explicitly)"
            )
          );
        }
      }

      if (rc.type === "aws_s3_bucket_acl") {
        if (PUBLIC_ACLS[a.acl]) {
          deny.push(finding("TF-S3-002", "high", rc.address, 'S3 bucket ACL resource uses "' + a.acl + '"'));
        }
      }

      if (rc.type === "aws_s3_bucket_public_access_block") {
        flags = [
          ["block_public_acls", a.block_public_acls],
          ["block_public_policy", a.block_public_policy],
          ["ignore_public_acls", a.ignore_public_acls],
          ["restrict_public_buckets", a.restrict_public_buckets],
        ];
        for (j = 0; j < flags.length; j++) {
          if (!flags[j][1]) {
            deny.push(finding("TF-S3-004", "high", rc.address, flags[j][0] + " is disabled"));
          }
        }
      }

      if (rc.type === "aws_security_group") {
        var ingress = a.ingress || [];
        for (j = 0; j < ingress.length; j++) {
          rule = ingress[j];
          if (sgWorldSensitive(rule) || sgWorldAllPorts(rule)) {
            deny.push(
              finding(
                "TF-SG-001",
                "high",
                rc.address,
                "Security group ingress opens ports " +
                  rule.from_port +
                  "-" +
                  rule.to_port +
                  "/" +
                  rule.protocol +
                  " to the world"
              )
            );
          }
        }
      }

      if (rc.type === "aws_security_group_rule" || rc.type === "aws_vpc_security_group_ingress_rule") {
        if (isIngressRule(rc)) {
          rule = normalizeSgRule(rc);
          if (sgWorldSensitive(rule) || sgWorldAllPorts(rule)) {
            deny.push(
              finding(
                "TF-SG-002",
                "high",
                rc.address,
                "Security group rule opens ports " +
                  rule.from_port +
                  "-" +
                  rule.to_port +
                  "/" +
                  rule.protocol +
                  " to the world"
              )
            );
          }
        }
      }

      if (rc.type === "aws_ebs_volume" && a.encrypted !== true) {
        deny.push(finding("TF-ENC-002", "high", rc.address, "EBS volume is not encrypted"));
      }

      if (rc.type === "aws_instance") {
        var root = a.root_block_device;
        if (Array.isArray(root)) {
          for (j = 0; j < root.length; j++) {
            if (root[j].encrypted !== true) {
              deny.push(finding("TF-ENC-002", "high", rc.address, "EC2 root_block_device is not encrypted"));
            }
          }
        } else if (root && typeof root === "object" && root.encrypted !== true) {
          deny.push(finding("TF-ENC-002", "high", rc.address, "EC2 root_block_device is not encrypted"));
        }
        var ebs = a.ebs_block_device || [];
        for (j = 0; j < ebs.length; j++) {
          if (ebs[j].encrypted !== true) {
            deny.push(
              finding(
                "TF-ENC-002",
                "high",
                rc.address,
                "EC2 ebs_block_device " + (ebs[j].device_name || "?") + " is not encrypted"
              )
            );
          }
        }
      }

      if ((rc.type === "aws_db_instance" || rc.type === "aws_rds_cluster") && a.storage_encrypted !== true) {
        deny.push(finding("TF-ENC-003", "high", rc.address, "RDS storage_encrypted is not true"));
      }

      if (TAGGABLE[rc.type]) {
        var tags = tagsOf(rc);
        for (j = 0; j < requiredTags.length; j++) {
          if (!tagPresent(tags, requiredTags[j])) {
            warn.push(finding("TF-TAG-001", "low", rc.address, 'Missing required tag "' + requiredTags[j] + '"'));
          }
        }
      }
    }

    function key(f) {
      return f.id + "|" + f.resource + "|" + f.msg;
    }
    deny.sort(function (a, b) {
      return key(a) < key(b) ? -1 : key(a) > key(b) ? 1 : 0;
    });
    warn.sort(function (a, b) {
      return key(a) < key(b) ? -1 : key(a) > key(b) ? 1 : 0;
    });

    return { deny: deny, warn: warn };
  }

  return {
    evaluate: evaluate,
    DEFAULT_TAGS: DEFAULT_TAGS,
    SENSITIVE_PORTS: SENSITIVE_PORTS,
  };
});
