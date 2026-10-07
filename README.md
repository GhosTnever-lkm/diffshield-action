# DiffShield 🛡️

**Review pull request changes for common security risks before they merge.** DiffShield is a dependency-free GitHub composite action that inspects only the Git diff between two commits and writes a readable report to the GitHub Actions job summary.

- Detects common credential formats and credential-like assignments in added lines. Secret values are never copied into annotations, the job summary, or the JSON report.
- Flags changed environment/key/credential files.
- Reviews changed GitHub Actions workflows for broad token permissions, unpinned external actions, direct interpolation of untrusted pull request text into `run:` commands (including YAML block scripts), and risky `pull_request_target` references.
- Notices changes to common dependency lock files.
- Adds file and line annotations, a 0–100 heuristic score, and a machine-readable `diffshield-report.json`.
- Runs locally on the GitHub-hosted runner, with Node.js built in. No API key, external scanner, network call, or third-party package is needed by DiffShield.

> DiffShield is a review aid, not a complete security audit. The risk score is a transparent heuristic, not a probability or certification. Pattern-based secret detection can miss credentials or flag examples. Rotate any credential that may have been exposed, even after deleting it from the current diff.

## Use in a repository

Add `.github/workflows/diffshield.yml`:

```yaml
name: DiffShield
on:
  pull_request:
permissions:
  contents: read
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - name: Check out source
        uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # refs/tags/v4, verified against actions/checkout
        with:
          fetch-depth: 0
          persist-credentials: false
      - name: Analyze pull request changes
        uses: GhosTnever-lkm/diffshield-action@ed6c7eedef8c77df131b03518f91c678a0c5686b # v1.0.0
        with:
          base-sha: ${{ github.event.pull_request.base.sha }}
          head-sha: ${{ github.event.pull_request.head.sha }}
          fail-on: high
```

For a security-sensitive workflow, pin **DiffShield itself** to a reviewed full commit SHA after selecting and verifying the release commit. The `@v1` example is convenient; a movable tag is not an immutable pin. Keep `pull_request` workflows free of repository secrets.

Inputs:

| Input | Required | Default | Meaning |
|---|---:|---:|---|
| `base-sha` | yes | — | Full 40-character base commit SHA |
| `head-sha` | yes | — | Full 40-character head commit SHA |
| `fail-on` | no | `high` | Fail CI at `critical`, `high`, `medium`, or `none` |
| `max-findings` | no | `100` | Maximum findings displayed in the summary (1–1000); all findings remain in the report |

Outputs: `risk-score`, `findings-count`. The step summary is available in the Actions run. `diffshield-report.json` is written into the checked-out workspace so later steps can upload it as an artifact if desired.

## Local development

Requires Node.js 20 or newer and Git. No `npm install` is needed.

```powershell
node --test test/scan.test.mjs
```

## Detection scope

The secret checks cover private-key headers, common GitHub/AWS/Google/Slack/Stripe tokens, bearer credentials, and assignments to names such as `password`, `secret`, `api_key`, or `access_token`. Example placeholders such as `YOUR_API_KEY` and `change_me` are filtered. The scanner examines added diff lines, not unchanged repository history; use a dedicated history scanner if a credential may have been committed earlier.

Workflow review is intentionally conservative and line-based; it is not a full YAML parser. Review every warning in context. DiffShield does not alter files, create comments, request write permissions, or make a merge decision.

## License

MIT. See [LICENSE](LICENSE).

## Security

Please report vulnerabilities privately through GitHub's **Report a vulnerability** feature. Do not publish working credentials in issues or pull requests.

Risk score weights are fixed and visible in the source: critical 40, high 25, medium 10, low 3, capped at 100. The score is not a probability.

