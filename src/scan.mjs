import { execFileSync } from 'node:child_process';
import { appendFileSync, writeFileSync } from 'node:fs';

const SEVERITY = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const BASE = process.env.DIFFSHIELD_BASE_SHA ?? '';
const HEAD = process.env.DIFFSHIELD_HEAD_SHA ?? '';
const failOn = (process.env.DIFFSHIELD_FAIL_ON ?? 'high').toLowerCase();
const maxFindings = Number.parseInt(process.env.DIFFSHIELD_MAX_FINDINGS ?? '100', 10);
const findings = [];

function add(severity, category, path, line, message, recommendation) {
  if (!SEVERITY[severity]) return;
  findings.push({ severity, category, path, line, message, recommendation });
}

function git(args) {
  return execFileSync('git', args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] });
}

function isPlaceholder(value) {
  return /^(?:example|sample|dummy|changeme|change_me|your[_ -]|replace[_ -]|<.+>|\*{4,}|x{4,})/i.test(value.trim());
}

function secretPattern(line) {
  const patterns = [
    ['Private key material', /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/],
    ['GitHub access token', /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/],
    ['AWS access key ID', /\bAKIA[0-9A-Z]{16}\b/],
    ['Google API key', /\bAIza[0-9A-Za-z_-]{30,}\b/],
    ['Slack token', /\bxox[baprs]-[0-9A-Za-z-]{20,}\b/],
    ['Stripe secret key', /\bsk_(?:live|test)_[0-9A-Za-z]{20,}\b/],
    ['Bearer credential', /\bBearer\s+[A-Za-z0-9._~+/-]{24,}={0,2}\b/i],
  ];
  for (const [name, regex] of patterns) if (regex.test(line)) return name;

  const assignment = line.match(/(?:password|passwd|secret|api[_-]?key|access[_-]?token|client[_-]?secret)\s*[:=]\s*["']?([^\s"',;]{8,})/i);
  if (assignment && !isPlaceholder(assignment[1]) && !/^\$\{\{|^\$[A-Z_][A-Z0-9_]*$/i.test(assignment[1])) {
    return 'Credential-like assignment';
  }
  return null;
}

function parseDiff(diff) {
  const files = [];
  let current = null;
  for (const line of diff.split(/\r?\n/)) {
    const header = line.match(/^diff --git a\/(.*) b\/(.*)$/);
    if (header) {
      current = { oldPath: header[1], path: header[2], added: [] };
      files.push(current);
      continue;
    }
    if (!current || line.startsWith('\\')) continue;
    const hunk = line.match(/^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,(\d+))? @@/);
    if (hunk) { current.newLine = Number(hunk[2]); continue; }
    if (line.startsWith('+++ ') || line.startsWith('--- ')) continue;
    if (line.startsWith('+')) { current.added.push({ text: line.slice(1), line: current.newLine ?? 1 }); current.newLine = (current.newLine ?? 1) + 1; }
    else if (line.startsWith(' ')) current.newLine = (current.newLine ?? 1) + 1;
  }
  return files;
}

function isWorkflow(path) {
  return /^\.github\/workflows\/[^/]+\.(?:yml|yaml)$/i.test(path);
}

function inspectWorkflow(file, text) {
  const lines = text.split(/\r?\n/);
  const all = text;
  if (/^\s*permissions\s*:\s*write-all\s*$/mi.test(all)) {
    add('critical', 'Workflow permissions', file.path, lineOf(lines, /permissions\s*:\s*write-all/i), 'Workflow grants write access to every token scope.', 'Grant only the permissions required by each job.');
  }
  if (/pull_request_target/.test(all)) {
    const refLine = lineOf(lines, /github\.event\.pull_request\.head\.(?:sha|ref)/);
    if (refLine) add('high', 'Untrusted pull request', file.path, refLine, 'Privileged pull_request_target workflow references a contributor-controlled head.', 'Avoid checking out or executing pull request code in pull_request_target workflows.');
  }
  let runBlockIndent = null;
  for (let i = 0; i < lines.length; i++) {
    const indentation = lines[i].match(/^\s*/)[0].length;
    const run = lines[i].match(/^(\s*)(?:-\s*)?run\s*:\s*(.*)$/i);
    if (run) runBlockIndent = !run[2] || /^[|>][+-]?$/.test(run[2].trim()) ? run[1].length : null;
    else if (runBlockIndent !== null && lines[i].trim() && indentation <= runBlockIndent) runBlockIndent = null;
    const isRunCommand = Boolean(run) || runBlockIndent !== null;
    if (isRunCommand && /\$\{\{\s*github\.event\.(?:pull_request\.(?:title|body)|issue\.title|comment\.body)/i.test(lines[i])) {
      add('high', 'Workflow script injection', file.path, i + 1, 'Untrusted pull request text is interpolated directly into a shell command.', 'Pass event values through an environment variable and quote them in the script.');
    }
    const uses = lines[i].match(/^\s*(?:-\s*)?uses\s*:\s*([^\s#]+)/i);
    if (uses && !uses[1].startsWith('./') && !uses[1].startsWith('docker://') && !/@[a-f0-9]{40}$/i.test(uses[1])) {
      add('medium', 'Action version pinning', file.path, i + 1, `External action is referenced by a movable tag: ${uses[1]}.`, 'Pin external actions to a verified full-length commit SHA.');
    }
  }
  if (!/^\s*permissions\s*:/mi.test(all)) {
    add('medium', 'Workflow permissions', file.path, 1, 'Workflow does not declare explicit token permissions.', 'Add a least-privilege permissions block, such as contents: read.');
  }
}

function lineOf(lines, regex) {
  const index = lines.findIndex(line => regex.test(line));
  return index < 0 ? 1 : index + 1;
}

function sensitivePath(path) {
  const lower = path.toLowerCase();
  const name = lower.split('/').at(-1);
  if (/^\.env(?:\.|$)/.test(name) && !/\.example$|\.sample$|\.template$/.test(name)) return true;
  return /^(?:id_rsa|id_ed25519|credentials\.json|service-account(?:-key)?\.json)$/.test(name)
    || /\.(?:pem|p12|pfx|key|keystore)$/i.test(name)
    || /(?:^|\/)(?:secrets|credentials)\.(?:ya?ml|json)$/i.test(path);
}

function riskScore(items) {
  return Math.min(100, items.reduce((sum, item) => sum + ({ critical: 40, high: 25, medium: 10, low: 3, info: 0 }[item.severity] ?? 0), 0));
}

function md(value) {
  return String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
    .replaceAll('|', '\\|').replaceAll('`', '&#96;').replaceAll('\r', ' ').replaceAll('\n', ' ');
}
function commandEscape(value) {
  return String(value).replaceAll('%', '%25').replaceAll('\r', '%0D').replaceAll('\n', '%0A')
    .replaceAll(':', '%3A').replaceAll(',', '%2C');
}

function main() {
  if (!/^[a-f0-9]{40}$/i.test(BASE) || !/^[a-f0-9]{40}$/i.test(HEAD)) throw new Error('base-sha and head-sha must be full 40-character commit SHAs.');
  if (!Object.hasOwn(SEVERITY, failOn)) throw new Error('fail-on must be critical, high, medium, or none.');
  if (!Number.isInteger(maxFindings) || maxFindings < 1 || maxFindings > 1000) throw new Error('max-findings must be an integer between 1 and 1000.');

  const diff = git(['diff', '--no-ext-diff', '--no-renames', '--unified=0', BASE, HEAD, '--']);
  const files = parseDiff(diff);
  const seenSecrets = new Set();
  for (const file of files) {
    if (file.added.length && sensitivePath(file.path)) {
      const key = `sensitive\0${file.path}`;
      if (!seenSecrets.has(key)) { add('high', 'Sensitive file', file.path, 1, 'A sensitive credential or private-key file was added or changed.', 'Remove it from the repository and rotate any credential that may have been exposed.'); seenSecrets.add(key); }
    }
    file.added.forEach(({ text, line }) => {
      const match = secretPattern(text);
      if (!match) return;
      const key = `${match}\0${file.path}`;
      if (!seenSecrets.has(key)) { add('critical', 'Possible secret', file.path, line, `${match} detected in an added line; its value is intentionally not shown.`, 'Revoke or rotate the credential, remove it from history, and use repository secrets.'); seenSecrets.add(key); }
    });
    if (isWorkflow(file.path)) {
      try { inspectWorkflow(file, git(['show', `${HEAD}:${file.path}`])); }
      catch { add('medium', 'Workflow inspection', file.path, 1, 'Could not read the final workflow version for analysis.', 'Confirm the file exists at the requested head commit.'); }
    }
    if (/^(?:package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|requirements(?:-[^/]+)?\.txt|Cargo\.lock|go\.sum|Gemfile\.lock)$/i.test(file.path.split('/').at(-1)) && file.added.length) {
      add('low', 'Dependency change', file.path, 1, 'Dependency lock data changed; review the package and source before merging.', 'Confirm the change is expected and generated by the package manager.');
    }
  }

  const score = riskScore(findings);
  const counts = Object.fromEntries(Object.keys(SEVERITY).map(level => [level, findings.filter(item => item.severity === level).length]));
  const report = { tool: 'DiffShield', version: '1.0.0', base: BASE, head: HEAD, riskScore: score, counts, findings };
  const summary = [];
  summary.push('## 🛡️ DiffShield analysis');
  summary.push('');
  summary.push(`**Heuristic risk score: ${score}/100** · ${findings.length} finding(s) · ${files.length} changed file(s)`);
  summary.push('');
  summary.push('This is an automated review aid, not a complete security audit. Finding a possible credential does not expose its value in logs or this report.');
  summary.push('');
  if (!findings.length) summary.push('✅ No configured checks reported a finding in the analyzed diff.');
  else {
    summary.push('| Severity | Category | Location | Finding | Suggested next step |');
    summary.push('|---|---|---|---|---|');
    for (const item of findings.slice(0, maxFindings)) summary.push(`| ${item.severity.toUpperCase()} | ${md(item.category)} | \`${md(item.path)}:${item.line}\` | ${md(item.message)} | ${md(item.recommendation)} |`);
    if (findings.length > maxFindings) summary.push('', `Showing ${maxFindings} of ${findings.length} findings. See workflow annotations for additional locations.`);
  }
  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (summaryPath) appendFileSync(summaryPath, `${summary.join('\n')}\n`, 'utf8');
  writeFileSync('diffshield-report.json', `${JSON.stringify(report, null, 2)}\n`, { encoding: 'utf8' });
  for (const item of findings) {
    const annotation = `::warning file=${commandEscape(item.path)},line=${item.line},title=${commandEscape(`DiffShield ${item.severity}`)}::${commandEscape(`${item.category}: ${item.message} ${item.recommendation}`)}`;
    console.log(annotation);
  }
  const outputs = process.env.GITHUB_OUTPUT;
  if (outputs) appendFileSync(outputs, `risk-score=${score}\nfindings-count=${findings.length}\n`, 'utf8');
  console.log(`DiffShield: ${findings.length} finding(s), risk score ${score}/100. Full report: diffshield-report.json`);

  const threshold = failOn === 'none' ? Infinity : SEVERITY[failOn];
  if (findings.some(item => SEVERITY[item.severity] >= threshold)) process.exitCode = 1;
}

main();

