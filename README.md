# macOS Privacy Permission Audit

A small Python tool that walks the macOS TCC (Transparency, Consent, and Control) databases, identifies which apps hold dangerous privacy permissions, flags ghost entries left behind by uninstalled apps, and renders a self-contained HTML report you can read in any browser.

Built with Python 3 and Jinja2. No daemon, no GUI; one script, one HTML output.

![Screenshot of the generated HTML report showing several dangerous-permission categories — Full Disk Access, Accessibility, Screen Recording — each with the apps that currently hold the grant and a per-category threat description.](docs/screenshot.png)

## What it does

macOS gates access to sensitive resources (camera, mic, files, screen recording, accessibility automation, etc.) through TCC. Every grant — and every *prior* grant for an app that has since been uninstalled — sits in one of two SQLite databases on disk. macOS's Settings UI shows you the surface; this tool reads the databases directly and surfaces:

- **Critical permissions:** Full Disk Access, Accessibility, Screen Recording, Input Monitoring.
- **High-risk permissions:** Camera, Microphone.
- **Medium-risk permissions:** Personal Data (Contacts, Calendar, Reminders, Bluetooth), Automation (Apple Events).
- **Ghost entries:** TCC rows whose `client` references an app that no longer exists on disk. These are the ones macOS forgets to clean up, and System Settings doesn't show them. TCC binds most grants to the app's code-signing requirement, so an unrelated app can't simply reuse the bundle ID and inherit them. Still, a reinstall from the same developer picks the grant back up without asking, and stale rows are worth reviewing and revoking.

Each category in the report includes:

- A plain-English threat description (what the permission lets an app do, and what a malicious app could do with it).
- The list of currently-granted apps, with friendly names resolved from bundle IDs.
- A per-row risk indicator and the source database (user-level vs. system-level).

## Install and run

Requires [uv](https://docs.astral.sh/uv/), which installs Python and the Jinja2 dependency on first run.

```bash
# Clone
git clone https://github.com/LunaParker/macos-permission-report.git
cd macos-permission-report

# Run
uv run generate_report.py
```

By default the report is written to `~/Downloads/privacy_audit.html`. Override with `--output`:

```bash
uv run generate_report.py --output ./report.html
```

Then open the file in your browser:

```bash
open ~/Downloads/privacy_audit.html
```

## Why I built it

I'm a security-spec'd CS student, and I wanted to know what was actually granted on my own Mac without trusting Settings → Privacy & Security to be exhaustive. Once I'd written the TCC reader I noticed the ghost-entry behaviour, which Settings doesn't expose at all. That seemed worth surfacing properly.

The script is also a useful diagnostic for things like proctoring software (LockDown Browser, Respondus, Honorlock) — they ask for invasive grants, often retain them after the exam window, and don't always show up cleanly in the GUI.

## TCC primer

There are two TCC databases, and they store different kinds of grants:

| Database | Path | What it stores |
|---|---|---|
| **User** | `~/Library/Application Support/com.apple.TCC/TCC.db` | Camera, Microphone, Contacts, Calendar, Reminders, Bluetooth, Apple Events (Automation), Media Library, Photos, folder access (Desktop, Documents, Downloads), iCloud Drive |
| **System** | `/Library/Application Support/com.apple.TCC/TCC.db` | Full Disk Access, Accessibility, Screen Recording, Input Monitoring, Developer Tools |

The system database can only be read by a process that itself holds Full Disk Access. Terminal usually does; many IDEs do not. See *Caveats* below.

The key table in each database is `access`. The columns this tool reads are:

| Column | Meaning |
|---|---|
| `service` | TCC service ID, e.g. `kTCCServiceCamera`, `kTCCServiceSystemPolicyAllFiles` |
| `client` | Bundle ID (`com.brave.Browser`) or absolute path |
| `client_type` | 0 = bundle identifier, 1 = absolute path |
| `auth_value` | 0 = denied, 2 = allowed, 3 = limited |
| `auth_reason` | Why it was set (2 = user, 3 = AppleEvents, 4 = system, 5 = system policy) |
| `indirect_object_identifier` | For Automation grants, the target app's bundle ID |

## How it works

1. **Open both TCC databases** read-only via SQLite. Skip the system DB gracefully if FDA isn't available; the user DB still produces a useful (partial) report.
2. **Find installed apps** with Spotlight (`mdfind`) across `/Applications`, `~/Applications`, and `/System/Applications`, falling back to a plain directory scan if Spotlight fails, and build a `bundle_id → InstalledApp` map by reading each `.app/Contents/Info.plist`. This is what later lets the report show *Brave Browser* instead of `com.brave.Browser`.
3. **For each grant**, classify by service into one of the eight categories, look up the friendly name (or fall back to the raw bundle ID / path), and assign a risk level.
4. **Detect ghost entries** by checking each grant's `client` against the installed-apps map. If no match: the grant is for an app that's no longer present.
5. **Render the HTML report** using Jinja2 against `template.html`. The output is fully self-contained — inline CSS, no JavaScript, no external assets — so it can be opened in any browser, emailed to yourself, or saved as a PDF.

## Caveats

- **Full Disk Access is required for the system-level grants.** That includes Full Disk Access itself, Accessibility, Screen Recording, Input Monitoring, and Developer Tools. If your Terminal app doesn't hold FDA, those sections of the report will be empty and the script prints a warning. To grant: System Settings → Privacy & Security → Full Disk Access → toggle Terminal (or iTerm). Running from a PyCharm or VS Code terminal usually does *not* work unless the IDE itself has FDA.
- **The TCC databases are not the complete privacy story.** Network access, location, motion, HomeKit, and HealthKit live elsewhere. This tool intentionally focuses on TCC because that's where the most sensitive grants (FDA, Screen Recording, Input Monitoring, Accessibility) are stored.
- **Ghost entries are not necessarily compromised.** They're TCC rows for apps that no longer exist on disk; that's a *risk surface*, not a confirmed problem. The point of surfacing them is so you can review and revoke deliberately.
- **The output report is sensitive.** It contains every app on the audited Mac plus the permissions each one holds — effectively a fingerprint of the machine. Don't commit it; don't post it raw. The repo's `.gitignore` already excludes `*.html` apart from the template.

## What's not (yet) covered

- Several user-database services aren't surfaced yet: Photos, Media Library, folder access (Desktop, Documents, Downloads), and iCloud Drive.
- Sandbox container access patterns (App Sandbox / Group Containers).
- TCC reset history (`tccutil reset` events) — TCC doesn't keep an audit log of revocations, so neither does this tool.

PRs welcome on any of the above.

## Contributing

The classifier is driven by two curated dictionaries near the top of `generate_report.py`:

- **`ASSESSMENTS`** — maps known app bundle IDs to per-permission assessments (`Expected` / `Review` / `Invasive`) plus a one-line tooltip explaining *why*. Use `_default` for an app-level fallback when a single rule covers most permissions, or per-service keys (e.g. `kTCCServiceSystemPolicyAllFiles`) when a single app legitimately holds some permissions but should raise eyebrows for others.
- **`INVASIVE_APPS`** — apps that are invasive *by design* (exam proctoring, employee monitoring, stealth keyloggers). Entries here also drive the red alert banner at the top of the report.

If you find an app the report mis-classifies — most often, an unknown app showing up as `Review` simply because its bundle ID isn't in `ASSESSMENTS` yet — that's exactly the gap to fill. PRs welcome. Keep the reason text short, concrete, and honest about *why* the permission is or isn't justified for that app's category.

## License

[MIT](LICENSE.md) — Luna Parker
