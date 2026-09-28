#!/usr/bin/env node
// every contract event field must be one the chain already makes public through calldata or
// storage; a new field needs a privacy review before it joins the allowlist.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

const root = new URL("../contracts/src", import.meta.url).pathname;
const publicFields = new Set([
  // deposit activation: the bridge call's arguments.
  "funding_commitment",
  "deposit_root",
  "note_root",
  // a transition: its header and the size of its padded output list.
  "seq",
  "new_book_root",
  "output_root",
  "output_count",
  // an external fill: the public ekubo swap it settled.
  "pair_id",
  "sell",
  "consumed_base",
  "pool_quote",
  "m1",
  // a withdrawal: the spent nullifier and the privacy-pool exit it releases.
  "nullifier",
  "matures_at",
  "exit_commitment",
]);

const failures = [];
for (const file of cairoFiles(root)) {
  const text = readFileSync(file, "utf8");
  const events = text.matchAll(/#\[derive\([^)]*starknet::Event[^)]*\)\]\s*pub struct (\w+)\s*\{([^}]*)\}/g);
  for (const [, name, body] of events) {
    for (const [, field] of body.matchAll(/pub (\w+):/g)) {
      if (!publicFields.has(field)) failures.push(`${file}: event ${name} exposes '${field}', which is not on the public allowlist`);
    }
  }
}

if (failures.length > 0) {
  console.error("contract event privacy check failed");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}
console.log("contract event privacy check passed");

function* cairoFiles(dir) {
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) yield* cairoFiles(path);
    else if (path.endsWith(".cairo")) yield path;
  }
}
