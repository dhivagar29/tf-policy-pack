#!/usr/bin/env node
/**
 * Compare playground/policy.js findings against `opa eval` on the same fixtures.
 * Exit 0 only when deny/warn sets match (by id+resource+severity+normalized message).
 */
const { readFileSync, existsSync } = require("node:fs");
const { spawnSync } = require("node:child_process");
const { dirname, join } = require("node:path");

const root = join(__dirname, "..");
const { evaluate } = require(join(root, "playground", "policy.js"));

const opa = process.env.OPA_BIN || join(process.env.HOME || "", ".local/bin/opa");
if (!existsSync(opa)) {
  console.error("opa binary not found at", opa);
  process.exit(2);
}

function opaFindings(fixturePath) {
  const query = "[object.union_n([{deny: data.main.deny}, {warn: data.main.warn}])]";
  // Use two evals for clarity
  function evalSet(rule) {
    const r = spawnSync(
      opa,
      ["eval", "-f", "json", "-i", fixturePath, "-d", join(root, "policy"), "-d", join(root, "data"), `data.main.${rule}`],
      { encoding: "utf8" }
    );
    if (r.status !== 0) {
      throw new Error(`opa eval ${rule} failed: ${r.stderr || r.stdout}`);
    }
    const parsed = JSON.parse(r.stdout);
    const value = (((parsed.result || [])[0] || {}).expressions || [])[0]?.value;
    return Array.isArray(value) ? value : value ? Array.from(value) : [];
  }
  return { deny: evalSet("deny"), warn: evalSet("warn") };
}

function normMsg(msg) {
  // Strip the structured prefix we add in both engines: [ID] (sev) resource: ...
  return String(msg).replace(/^\[[^\]]+\] \([^)]+\) [^:]+:\s*/, "");
}

function canon(findings) {
  return findings
    .map((f) => `${f.id}|${f.severity}|${f.resource}|${normMsg(f.msg)}`)
    .sort();
}

function compare(name, left, right) {
  const a = canon(left);
  const b = canon(right);
  const missing = b.filter((x) => !a.includes(x));
  const extra = a.filter((x) => !b.includes(x));
  if (missing.length || extra.length) {
    console.error(`Mismatch on ${name}`);
    if (missing.length) console.error("  missing from JS:\n   ", missing.join("\n    "));
    if (extra.length) console.error("  extra in JS:\n   ", extra.join("\n    "));
    return false;
  }
  console.log(`${name}: OK (${a.length} findings)`);
  return true;
}

const fixtures = ["fixtures/plan_bad.json", "fixtures/plan_good.json"];
let ok = true;
for (const rel of fixtures) {
  const path = join(root, rel);
  const plan = JSON.parse(readFileSync(path, "utf8"));
  const js = evaluate(plan, { requiredTags: ["Owner", "Environment", "CostCenter"] });
  const opaOut = opaFindings(path);
  console.log("==", rel, "==");
  ok = compare("deny", js.deny, opaOut.deny) && ok;
  ok = compare("warn", js.warn, opaOut.warn) && ok;
}

process.exit(ok ? 0 : 1);
