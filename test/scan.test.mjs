import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const scanner = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../src/scan.mjs');
function fixture(files, options = {}) {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'diffshield-'));
  const git = (...args) => execFileSync('git', args, { cwd: dir, stdio: 'ignore' });
  git('init', '-q'); git('config', 'user.email', 'diffshield-test@example.invalid'); git('config', 'user.name', 'DiffShield test');
  writeFileSync(path.join(dir, 'README.md'), 'fixture\n');
  git('add', '.'); git('commit', '-qm', 'base');
  const base = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: dir, encoding: 'utf8' }).trim();
  for (const [name, body] of Object.entries(files)) {
    const target = path.join(dir, name); mkdirSync(path.dirname(target), { recursive: true }); writeFileSync(target, body);
  }
  git('add', '-A'); git('commit', '-qm', 'head');
  const head = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: dir, encoding: 'utf8' }).trim();
  const result = spawnSync(process.execPath, [scanner], { cwd: dir, encoding: 'utf8', env: { ...process.env, DIFFSHIELD_BASE_SHA: base, DIFFSHIELD_HEAD_SHA: head, DIFFSHIELD_FAIL_ON: options.failOn ?? 'high' } });
  const report = JSON.parse(readFileSync(path.join(dir, 'diffshield-report.json'), 'utf8'));
  return { dir, result, report };
}

test('clean changes produce a zero-risk report', t => {
  const f = fixture({ 'src/app.js': 'export const value = 42;\n' }); t.after(() => rmSync(f.dir, { recursive: true, force: true }));
  assert.equal(f.result.status, 0); assert.equal(f.report.riskScore, 0); assert.equal(f.report.findings.length, 0);
});

test('credential detection reports line without copying secret value into logs', t => {
  const fake = ['ghp_', '123456789012345678901234567890123456'].join('');
  const f = fixture({ 'src/config.js': `export const key = "${fake}";\n` }); t.after(() => rmSync(f.dir, { recursive: true, force: true }));
  assert.notEqual(f.result.status, 0); assert.equal(f.report.findings[0].severity, 'critical'); assert.equal(f.report.findings[0].line, 1);
  assert.doesNotMatch(f.result.stdout + f.result.stderr, /123456789012345678901234567890123456/);
});

test('workflow issues are grouped and fail at the configured threshold', t => {
  const workflow = 'name: test\non: pull_request\njobs:\n  scan:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: |\n          echo ${{ github.event.pull_request.title }}\n';
  const f = fixture({ '.github/workflows/ci.yml': workflow }, { failOn: 'medium' }); t.after(() => rmSync(f.dir, { recursive: true, force: true }));
  assert.notEqual(f.result.status, 0);
  assert.ok(f.report.findings.some(x => x.category === 'Workflow script injection'));
  assert.ok(f.report.findings.some(x => x.category === 'Action version pinning'));
  assert.ok(f.report.findings.some(x => x.category === 'Workflow permissions'));
});

test('documented placeholders do not trigger credential assignment heuristic', t => {
  const f = fixture({ '.env.example': 'API_KEY=YOUR_API_KEY_HERE\n', 'app.js': 'const password = "change_me_now";\n' }); t.after(() => rmSync(f.dir, { recursive: true, force: true }));
  assert.equal(f.report.findings.filter(x => x.category === 'Possible secret' || x.category === 'Sensitive file').length, 0);
});
