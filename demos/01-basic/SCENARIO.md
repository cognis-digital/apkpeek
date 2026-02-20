# Demo 01 — Basic APK manifest triage

This demo shows APKPEEK scanning a small synthetic APK that intentionally
contains common Android security smells.

## What the demo builds

The test suite (`tests/test_smoke.py`) builds a real **ZIP-based `.apk`** on the
fly containing:

- `AndroidManifest.xml` — a plain-text manifest (APKPEEK also decodes Android's
  *binary* AXML format; plain text is used here so the fixture stays readable)
  with:
  - `android:debuggable="true"` on `<application>`
  - `android:allowBackup="true"`
  - `android:usesCleartextTraffic="true"`
  - an **exported** `<activity>` with no permission guard
  - an **exported** `<provider>` (higher severity)
  - a dangerous permission (`READ_SMS`)
- `assets/config.json` — containing a hard-coded **AWS access key id** and a
  **Google API key**.

The checked-in file `sample_manifest.xml` in this folder is the same manifest in
plain text so you can eyeball what gets flagged.

## Run it

```bash
# Table view
python -m apkpeek scan demos/01-basic/sample_manifest.xml

# JSON for CI / jq
python -m apkpeek scan demos/01-basic/sample_manifest.xml --format json | jq '.summary'

# SARIF for code-scanning dashboards
python -m apkpeek scan demos/01-basic/sample_manifest.xml --format sarif -o out.sarif
```

## Expected result

Scanning the manifest reports findings including:

| Rule          | Severity | What                                            |
|---------------|----------|-------------------------------------------------|
| APK-DEBUG     | high     | application is debuggable                       |
| APK-EXPORT    | high     | exported `<provider>` with no permission guard  |
| APK-EXPORT    | medium   | exported `<activity>`                           |
| APK-PERM      | high     | dangerous permission `READ_SMS`                 |
| APK-BACKUP    | medium   | `allowBackup=true`                              |
| APK-CLEARTEXT | medium   | cleartext traffic allowed                       |

Because there are findings at/above the default `--fail-on high` threshold, the
CLI exits with code **1** — perfect for failing a CI gate. Lower the gate with
`--fail-on critical` to allow these through, or raise sensitivity with
`--fail-on info`.
