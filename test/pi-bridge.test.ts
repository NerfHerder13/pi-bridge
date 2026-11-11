import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, test } from "node:test";
import { fileURLToPath } from "node:url";

const bridge = join(dirname(fileURLToPath(import.meta.url)), "../bin/pi-bridge");

/** Run the real launcher with a stub pi that prints the codemode worker limit it was started with. */
function workersFor(env: Record<string, string>): string {
	const dir = mkdtempSync(join(tmpdir(), "pi-bridge-test-"));
	const stub = join(dir, "pi");
	writeFileSync(stub, '#!/bin/sh\necho "${PI_CODEMODE_MAX_WORKERS-unset}"\n');
	chmodSync(stub, 0o755);
	const clean: Record<string, string> = { PATH: process.env.PATH ?? "", PI_BIN: stub };
	return execFileSync("bash", [bridge], { env: { ...clean, ...env }, encoding: "utf8" }).trim();
}

describe("pi-bridge codemode worker limit", () => {
	test("defaults to the default cap of 8 plus one", () => {
		assert.equal(workersFor({}), "9");
	});
	test("follows SUBAGENT_CONCURRENCY", () => {
		assert.equal(workersFor({ SUBAGENT_CONCURRENCY: "3" }), "4");
		assert.equal(workersFor({ SUBAGENT_CONCURRENCY: "16" }), "17");
	});
	test("raises a lower user value to cap + 1", () => {
		assert.equal(workersFor({ PI_CODEMODE_MAX_WORKERS: "2" }), "9");
		assert.equal(workersFor({ PI_CODEMODE_MAX_WORKERS: "8" }), "9");
	});
	test("leaves a higher user value alone", () => {
		assert.equal(workersFor({ PI_CODEMODE_MAX_WORKERS: "20" }), "20");
		assert.equal(workersFor({ SUBAGENT_CONCURRENCY: "3", PI_CODEMODE_MAX_WORKERS: "5" }), "5");
	});
	test("ignores an invalid SUBAGENT_CONCURRENCY or worker value", () => {
		assert.equal(workersFor({ SUBAGENT_CONCURRENCY: "abc" }), "9");
		assert.equal(workersFor({ SUBAGENT_CONCURRENCY: "0" }), "9");
		assert.equal(workersFor({ PI_CODEMODE_MAX_WORKERS: "lots" }), "9");
	});
});
