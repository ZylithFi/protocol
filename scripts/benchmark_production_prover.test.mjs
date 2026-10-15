import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import test from "node:test";

const script = readFileSync(new URL("./benchmark_production_prover.sh", import.meta.url), "utf8");

function select(executable) {
  const selector = script.split('case "${executable}" in')[1].split("esac")[0];
  return spawnSync("bash", ["-eu", "-c",
    `executable="$1"\ncase "\${executable}" in${selector}esac\nprintf '%s\\n%s\\n' "$benchmark_statement_kind" "$required_program_env"`,
    "benchmark-kind-test", executable], { encoding: "utf8" });
}

test("every statement executable routes to its pinned program", () => {
  const cases = [
    ["transition", "TRANSITION", "ZYLITH_TRANSITION_PROOF_PROGRAM_ADDRESS"],
    ["exchange_withdrawal", "WITHDRAWAL", "ZYLITH_WITHDRAWAL_PROOF_PROGRAM_ADDRESS"],
    ["residual_recovery", "RESIDUAL_RECOVERY", "ZYLITH_RESIDUAL_RECOVERY_PROOF_PROGRAM_ADDRESS"],
  ];
  const manifest = readFileSync(new URL("../stwo_statement/Scarb.toml", import.meta.url), "utf8");
  const declared = manifest.split("[[target.executable]]").slice(1)
    .map((section) => section.split('name = "')[1].split('"')[0]);
  assert.equal(declared.length, cases.length);
  for (const [executable, kind, program] of cases) {
    assert.ok(declared.includes(executable));
    const result = select(executable);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, `${kind}\n${program}\n`);
  }
});

test("unknown and retired benchmark names fail closed", () => {
  for (const name of ["", "exchange_residual_recovery", "benchmark", "transition;exit 0"]) {
    const result = select(name);
    assert.notEqual(result.status, 0, name);
    assert.equal(result.stdout, "");
    assert.match(result.stderr, /unsupported full SNIP-36 benchmark executable/);
  }
});

test("full proof and structured resource evidence remain mandatory", () => {
  for (const required of ["set -euo pipefail", "full SNIP-36 release benchmarks require a clean source tree",
    "ZYLITH_BENCHMARK_REQUIRE_RESOURCE_USAGE=1", '-- bench "${input_path}"']) {
    assert.ok(script.includes(required), required);
  }
  assert.ok(!script.includes('"${manifest}" prove'));
  const validator = script.split("<<'NODE'\n")[1].split("\nNODE")[0]
    .replace('fs.readFileSync(path, "utf8")', 'fs.readFileSync(0, "utf8")');
  const run = (input) => spawnSync(process.execPath, ["-e", validator], { input, encoding: "utf8" });
  const registry = JSON.stringify({ schema_version: 1, builtin_components: ["poseidon"], trace_components: ["cpu"] });
  const report = { schema_version: 3, identity: {}, resource_usage: {
    component_registry_id: createHash("sha256").update("zylith/proof-component-registry/v1:").update(registry).digest("hex"),
    raw_snos_steps: 100, adapted_rows: 128, memory_words: 100, memory_holes: 0,
    builtin_instances: { poseidon: 1 }, component_log_sizes: { cpu: 7 }, max_domain_log_size: 7,
    peak_rss_bytes: 100, wall_time_ms: 100,
  } };
  const valid = JSON.stringify(report);
  assert.equal(run(valid).status, 0);
  for (const input of ["", "{}", "proof failed", `${valid}\n${valid}`]) {
    assert.notEqual(run(input).status, 0, input);
  }
  for (const [field, value] of [["raw_snos_steps", 0], ["component_registry_id", "0".repeat(64)],
    ["component_log_sizes", {}], ["builtin_instances", {}]]) {
    const invalid = structuredClone(report);
    invalid.resource_usage[field] = value;
    assert.notEqual(run(JSON.stringify(invalid)).status, 0, field);
  }
});
