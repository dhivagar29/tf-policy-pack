# tf-policy-pack

OPA/Rego policy pack for Terraform plans (`terraform show -json`), runnable with [Conftest](https://www.conftest.dev/) in CI, plus a **browser-only** playground that evaluates the same rules client-side.

No cloud account required. Point Conftest at a plan JSON and get deny/warn findings with rule id, severity, resource address, and message.

## Why

Infrastructure misconfigurations (public buckets, world-open SSH/RDP/DB ports, missing encryption, missing ownership tags) still show up in plan review. This pack encodes a small, opinionated baseline you can run before apply.

## Rules

| ID | Severity | Rule | Signal |
| --- | --- | --- | --- |
| `TF-S3-001` | high (`deny`) | Public S3 ACL on `aws_s3_bucket` | `acl` is `public-read` or `public-read-write` |
| `TF-S3-002` | high (`deny`) | Public S3 ACL on `aws_s3_bucket_acl` | same ACL values |
| `TF-S3-003` | high (`deny`) | Missing public access block | bucket in plan without matching `aws_s3_bucket_public_access_block` |
| `TF-S3-004` | high (`deny`) | Disabled public access block flags | any of the four block flags is false |
| `TF-SG-001` | high (`deny`) | Open security group ingress | `0.0.0.0/0` or `::/0` on sensitive ports (22, 3389, DB ports) or all ports |
| `TF-SG-002` | high (`deny`) | Open standalone SG / VPC ingress rule | same CIDR/port checks on `aws_security_group_rule` and `aws_vpc_security_group_ingress_rule` |
| `TF-ENC-001` | high (`deny`) | S3 without SSE | no `aws_s3_bucket_server_side_encryption_configuration` (or legacy inline SSE) |
| `TF-ENC-002` | high (`deny`) | Unencrypted EBS | `aws_ebs_volume` / EC2 root or ebs block devices with `encrypted != true` |
| `TF-ENC-003` | high (`deny`) | Unencrypted RDS | `storage_encrypted != true` on `aws_db_instance` / `aws_rds_cluster` |
| `TF-TAG-001` | low (`warn`) | Missing required tags | configurable keys (default `Owner`, `Environment`, `CostCenter`) |

Required tag keys live in [`data/required_tags.json`](data/required_tags.json):

```json
{
  "required_tags": {
    "keys": ["Owner", "Environment", "CostCenter"]
  }
}
```

## Quick start (Conftest)

```bash
terraform plan -out=tfplan.binary
terraform show -json tfplan.binary > plan.json

conftest test plan.json -p policy --data data
```

Sample output from the bundled bad fixture is in [`docs/sample-output.txt`](docs/sample-output.txt).

## OPA unit tests

Pinned tooling used while developing this pack: **OPA 1.22.2**, **Conftest 0.71.1** (checksum-verified from GitHub release assets).

```bash
opa test policy/ data/ -v
```

## Playground (client-side only)

Open [`playground/index.html`](playground/index.html) in a browser (or serve the folder locally). Paste plan JSON, click **Evaluate**.

- Evaluation runs entirely in the browser via a faithful JavaScript port of the Rego rules (`playground/policy.js`).
- **No network calls**, **no CDN**, **no analytics**, **no cookies**, **no `localStorage`**.
- Strict CSP: `default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'none'; …`
- Sync test: `node scripts/sync-check.cjs` compares JS findings to `opa eval` on the same fixtures.

This repository does **not** deploy the playground.

## CI

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on push/PR with `permissions: contents: read`, third-party actions pinned to full commit SHAs, checksum-verified OPA/Conftest installs, `opa test`, Conftest on good/bad fixtures, and the playground sync check.

## Layout

```
policy/          Rego v1 policies + opa test files
data/            required tag configuration
fixtures/        good/bad terraform plan JSON
playground/      static HTML/JS/CSS policy evaluator
scripts/         sync-check.cjs (JS vs OPA)
docs/            sample Conftest output + playground screenshot
```

## Limits

- Evaluates **planned** create/update resources from `resource_changes[].change.after`. Destroy-only and read-only changes are ignored.
- Public-access-block and SSE linkage uses Terraform resource **name** and/or the `bucket` attribute string in the plan. Complex `for_each` / remote-state references may not correlate.
- Sensitive ports are a fixed set (SSH, RDP, common DB/cache). Customize in `policy/helpers.rego` (and mirror in `playground/policy.js`).
- Tag policy is warn-only and case-insensitive on keys; it does not validate tag *values*.
- Not a replacement for AWS Config, SCP, or provider-side defaults (S3 Block Public Access account settings, etc.).
- Playground is for demos and local review; CI should run Conftest/OPA on real plan JSON.

## License

MIT — see [LICENSE](LICENSE).
