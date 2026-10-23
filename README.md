# Windows patch level for Microsoft Defender for Endpoint

An automatically maintained catalog of every Windows monthly security release (Windows Vista → 11,
Windows Server 2008 → 2025 and anything Microsoft adds later). MDE KQL and a Power BI dashboard use it
to show each device's **patch month (MMM-YYYY)**, **how many security releases it is behind**, and
**how many CVEs (critical / exploited) it is missing**.

```
 Microsoft MSRC API ──► GitHub Actions (scheduled) ──► data/Windows_Security_Releases.csv (stable URL)
                         build → validate → archive old                │
                         → commit → Teams / email                      ▼
                                              MDE Advanced Hunting (externaldata + device builds)
                                                                       │
                                                                       ▼
                                                              Power BI dashboard
```

## What is in the repo

| Path | Purpose |
|---|---|
| `data/Windows_Security_Releases.csv` | **The catalog.** Stable URL: `https://raw.githubusercontent.com/jaydxt/Windows_Release_History/master/data/Windows_Security_Releases.csv` |
| `data/archive/Windows_Security_Releases_MMYYYY.csv` | Previous versions, archived automatically when new releases arrive |
| `data/cache/msrc/` | Compact per-month extracts, so a run downloads only new or revised months |
| `.github/workflows/update-catalog.yml` | The schedule (runs on GitHub, no device needed): daily on the 8th–16th and every Monday |
| `scripts/build_catalog.py` | Builds the catalog from the MSRC API, validates it and archives the previous file (standard-library Python) |
| `scripts/notify.py` | Teams and email notifications |
| `scripts/windows/` | Optional: run the job from Windows Task Scheduler on your own device instead |
| `kql/DevicePatchLevel.kql` | Device patch level query for Defender Advanced Hunting |
| `kql/00_CheckDeviceBuildSource.kql` | One-time check that your tenant reports full OS builds |
| `powerbi/` | The Power BI report, Power Query files, DAX measures and build guide |
| `docs/NOTIFICATIONS.md` | How to get the Teams webhook URL and SMTP details |
| `docs/SCHEDULING.md` | Where the schedule runs; Task Scheduler setup for another device |
| `docs/SECURITY.md` | Least-privilege design |

The older files in the repository root (`Windows_Release_History*.csv`, `windowsReleaseHistory.py`)
belong to the previous manual process. They are left untouched so existing queries keep working.

## One-time setup

1. Repo **Settings → Actions → General → Workflow permissions → Read and write permissions**.
2. Notifications (optional): `docs/NOTIFICATIONS.md`.
3. In Defender Advanced Hunting, run `kql/00_CheckDeviceBuildSource.kql`, then `kql/DevicePatchLevel.kql`.
4. Power BI: open `powerbi/Windows Patch Level.pbix` and follow `powerbi/README.md`.

## How a device is classified

The device's full OS build (e.g. `10.0.26100.9445`) is matched on **Platform (Client/Server) + build
number**, because Windows 11 24H2 and Server 2025 share build 26100. Its **patch month** is the newest
monthly security release whose build revision is ≤ the device's revision, so preview and out-of-band
builds count as the month they contain.

| VersionStatus | Meaning |
|---|---|
| Verified | Build found, patch month determined |
| Older than catalog history | Older than the first release with a published build (Microsoft published builds from 2021 on) |
| Unverified version – OS build not in Microsoft security catalog | Insider/preview, unknown or non-standard build |
| Unverified version – build revision not reported | Defender did not report the full build for this device |

| PatchStatus | RiskLevel |
|---|---|
| Current | Low |
| 1 month behind | Medium |
| 2 months behind | High |
| 3–5 / 6+ months behind | Critical |
| Unsupported OS (no longer receives security releases) | Critical |
| Unverified version | Unknown |

Thresholds are at the top of the KQL (`MediumAt`, `HighAt`, `CriticalAt`).

## Catalog columns

`OSFamily, OSName, Platform, BuildNumber, Revision, FullBuild, KB, UpdateType, PatchMonth (MMM-YYYY),
PatchMonthStart, ReleaseDate, ReleaseRank (1 = newest for that OS), IsLatestForOS, CVECount,
CriticalCVECount, ExploitedCVECount, CVEsReleasedSince / CriticalCVEsReleasedSince /
ExploitedCVEsReleasedSince (fixed by newer releases, i.e. missed by a device on this release),
OSLatestPatchMonth, OSLatestFullBuild, OSStillServiced, MsrcDocumentId`

Only **security** releases are included (Patch Tuesday cumulative/rollup updates). Optional preview
updates and feature updates are not counted as "missed".

## How the data is derived

MSRC publishes one CVRF document per month listing every CVE and the KB/build that fixes it per product.
Microsoft also revises old documents to reference newer KBs, so the script dates each build to the month
whose document it fixes the most CVEs in. It then keeps the build sequence that rises month on month, and
drops one-off entries that fix only a handful of CVEs. A run fails without publishing if the result looks
wrong: too few rows, a >5% row drop, the latest month going backwards, duplicates, or no serviced
Windows 11/Server version. A failed run sends a notification and the dashboard keeps the last good data.

## Maintenance

- **Nothing monthly.** New Windows versions are picked up automatically when Microsoft first ships a
  security update for them.
- Full rebuild: **Run workflow** with *full_refresh* ticked.
- GitHub pauses scheduled workflows after 60 days with no repository activity. The bot's own commits
  normally keep it active; if it is ever paused, re-enable it on the Actions tab.
- Local run (Python 3.10+, no packages needed): `python -I scripts/build_catalog.py`.
- After editing the KQL, run `python scripts/export_powerbi_query.py` to refresh the Power BI query.
