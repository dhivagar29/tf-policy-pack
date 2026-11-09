# tf-policy-pack

OPA/Rego policy pack for Terraform plans (`terraform show -json`), runnable with [Conftest](https://www.conftest.dev/) in CI, plus a **browser-only** playground that evaluates the same rules client-side.

No cloud account required. Point Conftest at a plan JSON and get deny/warn findings with rule id, severity, resource address, and message.

## Why

Infrastructure misconfigurations (public buckets, world-open SSH/RDP/DB ports, missing encryption, missing ownership tags) still show up in plan review. This pack encodes a small, opinionated baseline you can run before apply.

## Rules

| ID | Severity | Rule | Signal |
| --- | --- | --- | --- |
| `TF-S3-001` | high (`deny`) | Public / authenticated-read S3 ACL on `aws_s3_bucket` | `acl` is `public-read`, `public-read-write`, or `authenticated-read` |
| `TF-S3-002` | high (`deny`) | Public / authenticated-read S3 ACL on `aws_s3_bucket_acl` | same ACL values |
| `TF-S3-003` | high (`deny`) | Missing public access block | bucket in plan without matching `aws_s3_bucket_public_access_block` in the same module |
| `TF-S3-004` | high (`deny`) | Disabled public access block flags | any of the four block flags is false |
| `TF-SG-001` | high (`deny`) | Open security group ingress | `0.0.0.0/0` or `::/0` on sensitive ports (22, 3389, DB ports) or all ports |
| `TF-SG-002` | high (`deny`) | Open standalone SG / VPC ingress rule | same CIDR/port checks on `aws_security_group_rule` and `aws_vpc_security_group_ingress_rule` |
| `TF-ENC-001` | low (`warn`) | S3 without explicit SSE | no `aws_s3_bucket_server_side_encryption_configuration` (or legacy inline SSE); AWS has SSE-S3 by default since Jan 2023 |
| `TF-ENC-002` | high (`deny`) | Unencrypted EBS | `aws_ebs_volume` / EC2 root or ebs block devices with `encrypted != true` |
| `TF-ENC-003` | high (`deny`) | Unencrypted RDS | `storage_encrypted != true` on `aws_db_instance` / `aws_rds_cluster` |
| `TF-TAG-001` | low (`warn`) | Missing required tags | configurable keys (default `Owner`, `Environment`, `CostCenter`); prefers `tags_all` so provider `default_tags` count |

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

Pinned tooling used while developing this pack: **OPA 1.22.2**, **Conftest 0.71.1** (SHA256 values hardcoded in CI; verified against official GitHub release assets).

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

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on push/PR with `permissions: contents: read`, third-party actions pinned to full commit SHAs, OPA/Conftest installs verified against hardcoded SHA256 env constants, `opa test`, Conftest on good/bad fixtures, and the playground sync check.

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
- Public-access-block and SSE linkage uses Terraform resource **name** and/or the `bucket` attribute string in the plan, scoped by `module_address`. Complex `for_each` / remote-state references may not correlate.
- Sensitive ports are a fixed set (SSH, RDP, common DB/cache). Customize in `policy/helpers.rego` (and mirror in `playground/policy.js`).
- Sensitive-port matching ignores protocol, so UDP 22 is flagged.
- Tag policy is warn-only and case-insensitive on keys; it prefers `tags_all` (provider `default_tags`) and falls back to `tags`. It does not validate tag *values*.
- There is no rule for `aws_launch_template` block devices.
- Account-level default EBS and RDS encryption appears as unknown in the plan, so volumes/instances that rely on it can be flagged.
- Public bucket policies (`aws_s3_bucket_policy` with `Principal: "*"`) are not checked.
- New buckets have had public access blocked by default since April 2023, so `TF-S3-003` means "make the block explicit in the plan".
- Not a replacement for AWS Config, SCP, or provider-side defaults (S3 Block Public Access account settings, etc.).
- Playground is for demos and local review; CI should run Conftest/OPA on real plan JSON.
- Bucket matching also requires the same `module_address`, so a public access block or SSE config in one module that names a bucket in another module by literal name still raises TF-S3-003 / TF-ENC-001. This errs on the safe side (false positive, nothing missed).


## License

MIT — see [LICENSE](LICENSE).
