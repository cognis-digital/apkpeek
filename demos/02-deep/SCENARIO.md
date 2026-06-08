# Demo 02 — deep scan of a banking-trojan-shaped APK

This demo exercises the full MobSF-style engine on a deliberately dangerous app
(`com.example.bankspy`, masquerading as "WeatherPlus").

## Build the demo APK (real zip-format .apk)

```bash
python demos/02-deep/build_apk.py
# -> demos/02-deep/bankspy-demo.apk
```

## Scan it

```bash
python -m apkpeek scan demos/02-deep/bankspy-demo.apk
python -m apkpeek scan demos/02-deep/bankspy-demo.apk --format json | jq '.security_score'
python -m apkpeek manifest demos/02-deep/bankspy-demo.apk
```

You can also point the engine straight at the raw XML files (no build step):

```bash
python -m apkpeek scan demos/02-deep/AndroidManifest.xml
python -m apkpeek scan demos/02-deep/network_security_config.xml
```

## What the engine should flag

Manifest:
- `APK-DEBUG` (high) — debuggable=true
- `APK-BACKUP` (medium) — allowBackup=true
- `APK-CLEARTEXT` (high) — usesCleartextTraffic=true
- `APK-MINSDK` / `APK-TARGETSDK` (medium) — minSdk 19 / targetSdk 28
- `APK-PERM` (high) — RECEIVE_SMS, READ_SMS, overlay/accessibility perms
- `APK-PERM-COMBO` (high) — notification+accessibility, SMS+internet, overlay+accessibility
- `APK-CUSTOMPERM` — C2_CALLBACK declared protectionLevel=normal
- `APK-EXPORT` (high) — ExfilProvider exported, no guard
- `APK-EXPORT` (medium) — SmsInterceptor implicitly exported
- `APK-EXPORT` (low) — SyncService exported but permission-guarded
- `APK-TASKHIJACK` (medium) — PhishOverlayActivity singleTask + taskAffinity

Network security config:
- `NSC-CLEARTEXT-BASE` (high), `NSC-CLEARTEXT-DOMAIN` (medium)
- `NSC-USER-CA` (high) — trusts user CAs
- `NSC-NO-PINNING` (low)

Secrets (assets/secrets.json):
- `SEC-AWS-AKID`, `SEC-GOOGLE-API`, `SEC-GITHUB-PAT`, `SEC-STRIPE`,
  `SEC-SLACK-WEBHOOK`, `SEC-IP-URL`, `SEC-ENTROPY` (session_secret)

The combined report should produce an **F** grade.
