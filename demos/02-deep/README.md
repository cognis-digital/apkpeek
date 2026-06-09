# apkpeek deep demo - analyzing a deliberately leaky Android app

This demo ships two fixtures for `com.example.leakybank`, a fictional banking
app riddled with the issues MobSF-style scanners look for:

| file | what it is |
| --- | --- |
| `AndroidManifest.xml` | a **plain-text / decoded** manifest |
| `leakybank.apk` | a **real `.apk`** (ZIP) with a **binary (compiled AXML)** `AndroidManifest.xml`, a fake `classes.dex` and a `resources.arsc`, all carrying secrets |

`leakybank.apk` is produced by `build_fixture_apk.py`, which hand-encodes the
Android compiled-XML chunk format - so the demo proves apkpeek's AXML decoder,
not just its text parser.

## Try it

```console
$ python -m apkpeek scan demos/02-deep/leakybank.apk
$ python -m apkpeek manifest demos/02-deep/AndroidManifest.xml
$ python -m apkpeek permissions demos/02-deep/AndroidManifest.xml
$ python -m apkpeek secrets demos/02-deep/leakybank.apk --format json
```

## What it flags

* **debuggable** application build (`android:debuggable="true"`)
* **allowBackup** left enabled (adb data exfiltration)
* **cleartext HTTP** explicitly enabled (and, in text form, no network-security config)
* **exported components** with no permission guard - an activity, a service,
  an SMS broadcast `receiver` (exported implicitly via its intent-filter), and a
  **content `provider`** (flagged *critical*)
* **high-risk / signature permissions**: `BIND_ACCESSIBILITY_SERVICE`,
  `SYSTEM_ALERT_WINDOW`, `WRITE_SECURE_SETTINGS`, `READ_SMS`
* **hard-coded secrets**: a Google API key, an AWS access key, a Stripe live
  secret, a GitHub PAT, a Slack token and an RSA private-key block - recovered
  from both the manifest and the DEX/resource string tables.

`scan` exits non-zero (2) whenever any finding is present, so it drops straight
into a CI gate.

To rebuild the binary APK fixture:

```console
$ python demos/02-deep/build_fixture_apk.py
```
