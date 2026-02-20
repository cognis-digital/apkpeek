# APKPEEK — Architecture

> One-command static triage of Android APK/AAB binaries: surfaces hardcoded secrets, exported components, dangerous permissions, and insecure manifest flags as a single SARIF report.

```
input ──▶ collect ──▶ rules/analyzers ──▶ score ──▶ findings ──▶ table · json
                              │                          │
                         (this repo)                 MCP tool (agents)
```

- **collect** normalizes the target (file/dir/API) into records.
- **rules/analyzers** apply the heuristics shipped in `apkpeek/core.py`.
- **score** ranks by severity.
- **MCP server** (`apkpeek mcp`) exposes `scan` for Cognis.Studio agents.

Extend by adding a rule + a test + a `demos/NN-*/SCENARIO.md`. See [CONTRIBUTING.md](../CONTRIBUTING.md).
