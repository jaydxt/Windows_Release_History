# Power BI dashboard – build guide (about 20 minutes, one time)

The ready-made report is `Windows Patch Level.pbix` (see `powerbi/README.md`). This guide is for
rebuilding it by hand or adding pages. Prerequisites: Power BI Desktop and a Defender account that
can run Advanced Hunting.

## 1. Load the two tables

1. **Home → Get data → Blank query → Advanced Editor**, paste `DevicePatchLevel.pq`, **Done**.
   Rename the query to `DevicePatchLevel`. When prompted for credentials choose
   **Organizational account → Sign in → Connect**.
2. Repeat with `WindowsSecurityReleases.pq`, rename to `WindowsSecurityReleases`.
   Credentials: **Anonymous**.
3. **Close & Apply**.

## 2. Model settings

- `DevicePatchLevel[PatchMonth]` → Column tools → **Sort by column** → `PatchMonthStart`
- `DevicePatchLevel[PatchStatus]` → **Sort by column** → `PatchStatusOrder`
- `WindowsSecurityReleases[PatchMonth]` → **Sort by column** → `PatchMonthStart`
- Relationship: none needed (the KQL already joined the catalog). Delete any auto-detected one.
- Add the measures from `Measures.dax` (Modeling → New measure). Format `% Current` as Percentage.

## 3. Page 1 – "Patch risk overview"

| Area | Visual | Fields |
|---|---|---|
| Top row | 6 × **Card** | `Devices`, `% Current`, `Devices Critical Risk`, `Devices Unsupported OS`, `Devices Unverified`, `Avg Patches Behind` |
| Top right | **Card** | `Latest Patch Month` (title "Latest Microsoft release") |
| Left middle | **Donut** | Legend `PatchStatus`, Values `Devices` |
| Right middle | **Stacked bar** | Y-axis `OSName`, X-axis `Devices`, Legend `PatchStatus` |
| Bottom left | **Clustered column** | X-axis `PatchMonth`, Y-axis `Devices` (title "Devices by installed patch month") |
| Bottom right | **Table** | `DeviceName`, `OSName`, `DeviceOSBuild`, `PatchMonth`, `PatchesBehind`, `CriticalCVEsMissed`, `ExploitedCVEsMissed`, `RiskLevel`, `LastSeen` – sort by `PatchesBehind` descending |
| Slicers (left strip) | **Slicer** × 4 | `MachineGroup`, `Platform`, `OSName`, `RiskLevel` |
| Footer | **Card** | `Data As Of` |

Status colours (Format → Data colors, set once per visual):

| PatchStatus | Colour |
|---|---|
| Current | `#2E7D32` |
| 1 month behind | `#F9A825` |
| 2 months behind | `#EF6C00` |
| 3-5 months behind | `#D84315` |
| 6+ months behind | `#B71C1C` |
| Unsupported OS | `#4A148C` |
| Unverified version | `#9E9E9E` |

## 4. Page 2 – "Windows release catalog"

| Visual | Fields |
|---|---|
| **Table** (filter `IsLatestForOS` = True) | `OSName`, `Platform`, `OSLatestPatchMonth`, `OSLatestFullBuild`, `KB`, `OSStillServiced` |
| **Table** | `OSName`, `PatchMonth`, `KB`, `FullBuild`, `CVECount`, `CriticalCVECount`, `ExploitedCVECount` – slicer on `OSName` |

## 5. Page 3 – "Needs attention" (optional)

Duplicate the device table, add visual-level filters `RiskLevel` is `Critical` or `High`, and
`ExploitedCVEsMissed` > 0. Use this page for export/hand-off to the patching team.

## 6. Publish and schedule refresh

1. **File → Save** as `Windows Patch Level.pbix`, then **Publish** to a workspace.
2. In the Power BI service: workspace → semantic model → **Settings → Data source credentials**:
   - `api.securitycenter.microsoft.com` → OAuth2, sign in (organizational account)
   - `raw.githubusercontent.com` → Anonymous
3. **Scheduled refresh** → On, daily (e.g. 07:00 local). The catalog refreshes itself on GitHub;
   the device data refreshes on this schedule.

## Limits to know

- Advanced Hunting API: up to 100,000 rows and 10 minutes per query. For larger estates, add
  `| where MachineGroup in (...)` per report or move to Sentinel/Log Analytics as the source.
- The query reads devices seen in the last 30 days (`LookbackDays` at the top of the KQL).
