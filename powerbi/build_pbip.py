"""Generate the "Windows Patch Level" Power BI project (PBIP: model.bim + PBIR report).

Open the generated .pbip in Power BI Desktop, refresh, and File > Save as > .pbix.
  python powerbi/build_pbip.py [--theme-file <CY26SU10.json from Power BI Desktop>]

The device query is generated from kql/DevicePatchLevel.kql, so the KQL stays the single source.
A "DataSource" parameter switches between Defender (your tenant) and built-in sample devices.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import random
import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NAME = "Windows Patch Level"
OUT = ROOT / "powerbi" / "pbip"
CATALOG_URL_PATH = "jaydxt/Windows_Release_History/master/data/Windows_Security_Releases.csv"
SCHEMA = "https://developer.microsoft.com/json-schemas/fabric/item"
THEME = "CY26SU10"
DEV = "DevicePatchLevel"
CAT = "WindowsSecurityReleases"

# Status colours (dataviz reference status palette: good / warning / serious / critical), always shown
# with a text label. Magnitudes use one sequential blue; categories use the fixed categorical order.
STATUS_COLORS = {
    "Current": "#0CA30C", "1 month behind": "#FAB219", "2 months behind": "#EC835A",
    "3-5 months behind": "#D03B3B", "6+ months behind": "#8F2424",
    "Unsupported OS": "#6250D6", "Unverified version": "#8A8A86",
}
RISK_COLORS = {"Low": "#0CA30C", "Medium": "#FAB219", "High": "#EC835A", "Critical": "#D03B3B", "Unknown": "#8A8A86"}
UI = {
    "rail": "#0E1726", "rail_text": "#AEB8C8", "rail_active": "#1D2A40", "accent": "#2A78D6",
    "canvas": "#F3F5F8", "card": "#FFFFFF", "border": "#E6E9EF", "ink": "#0B0B0B", "ink2": "#52514E",
    "muted": "#8A8A86", "blue": "#2A78D6", "blue_light": "#CDE2FB", "blue_mid": "#86B6EF",
}

# (column, model dataType, M type)
DEVICE_COLUMNS = [
    ("LastSeen", "dateTime", "type datetime"), ("DeviceId", "string", "type text"),
    ("DeviceName", "string", "type text"), ("MachineGroup", "string", "type text"),
    ("ExposureLevel", "string", "type text"), ("OSPlatform", "string", "type text"),
    ("OSArchitecture", "string", "type text"), ("OSName", "string", "type text"),
    ("DeviceOSBuild", "string", "type text"), ("Platform", "string", "type text"),
    ("BuildNumber", "int64", "Int64.Type"), ("PatchMonth", "string", "type text"),
    ("PatchMonthStart", "dateTime", "type date"), ("InstalledSecurityKB", "string", "type text"),
    ("PatchesBehind", "int64", "Int64.Type"), ("CVEsMissed", "int64", "Int64.Type"),
    ("CriticalCVEsMissed", "int64", "Int64.Type"), ("ExploitedCVEsMissed", "int64", "Int64.Type"),
    ("LatestPatchMonth", "string", "type text"), ("LatestBuild", "string", "type text"),
    ("OSStillServiced", "boolean", "type logical"), ("VersionStatus", "string", "type text"),
    ("PatchStatus", "string", "type text"), ("PatchStatusOrder", "int64", "Int64.Type"),
    ("RiskLevel", "string", "type text"), ("DataSource", "string", "type text"),
    ("RiskOrder", "int64", "Int64.Type"),
]
DERIVED_DEVICE_COLUMNS = {"DataSource", "RiskOrder"}  # added in Power Query, not by the KQL
CATALOG_COLUMNS = [
    ("OSFamily", "string", "type text"), ("OSName", "string", "type text"), ("Platform", "string", "type text"),
    ("BuildNumber", "int64", "Int64.Type"), ("Revision", "int64", "Int64.Type"), ("FullBuild", "string", "type text"),
    ("KB", "string", "type text"), ("UpdateType", "string", "type text"), ("PatchMonth", "string", "type text"),
    ("PatchMonthStart", "dateTime", "type date"), ("ReleaseDate", "dateTime", "type date"),
    ("ReleaseRank", "int64", "Int64.Type"), ("IsLatestForOS", "boolean", "type logical"),
    ("CVECount", "int64", "Int64.Type"), ("CriticalCVECount", "int64", "Int64.Type"),
    ("ExploitedCVECount", "int64", "Int64.Type"), ("CVEsReleasedSince", "int64", "Int64.Type"),
    ("CriticalCVEsReleasedSince", "int64", "Int64.Type"), ("ExploitedCVEsReleasedSince", "int64", "Int64.Type"),
    ("OSLatestPatchMonth", "string", "type text"), ("OSLatestFullBuild", "string", "type text"),
    ("OSStillServiced", "boolean", "type logical"), ("MsrcDocumentId", "string", "type text"),
]

MEASURES = [
    ("Devices", f"DISTINCTCOUNT ( {DEV}[DeviceId] )", "#,0"),
    ("Devices Current", f'CALCULATE ( [Devices], {DEV}[PatchStatus] = "Current" )', "#,0"),
    ("% Current", "DIVIDE ( [Devices Current], [Devices] )", "0.0%"),
    ("Compliance Target", "0.95", "0%"),
    ("Gauge Max", "1", "0%"),
    ("Devices Behind", f"CALCULATE ( [Devices], {DEV}[PatchesBehind] >= 1 )", "#,0"),
    ("Devices 3+ Behind", f"CALCULATE ( [Devices], {DEV}[PatchesBehind] >= 3 )", "#,0"),
    ("Devices Critical Risk", f'CALCULATE ( [Devices], {DEV}[RiskLevel] = "Critical" )', "#,0"),
    ("Devices Unsupported OS", f'CALCULATE ( [Devices], {DEV}[PatchStatus] = "Unsupported OS" )', "#,0"),
    ("Devices Unverified", f'CALCULATE ( [Devices], {DEV}[PatchStatus] = "Unverified version" )', "#,0"),
    ("Avg Patches Behind", f"AVERAGEX ( FILTER ( {DEV}, NOT ISBLANK ( {DEV}[PatchesBehind] ) ), {DEV}[PatchesBehind] )", "0.0"),
    ("Devices Missing Exploited CVEs", f"CALCULATE ( [Devices], {DEV}[ExploitedCVEsMissed] > 0 )", "#,0"),
    ("CVE Exposures", f"SUM ( {DEV}[CVEsMissed] )", "#,0"),
    ("Critical CVE Exposures", f"SUM ( {DEV}[CriticalCVEsMissed] )", "#,0"),
    ("Exploited CVE Exposures", f"SUM ( {DEV}[ExploitedCVEsMissed] )", "#,0"),
    ("% Current Clients", f'CALCULATE ( [% Current], {DEV}[Platform] = "Client" )', "0.0%"),
    ("% Current Servers", f'CALCULATE ( [% Current], {DEV}[Platform] = "Server" )', "0.0%"),
    ("Risk Color", f'SWITCH ( SELECTEDVALUE ( {DEV}[RiskLevel] ), "Critical", "#B42323", "High", "#C25A2E", '
                   f'"Medium", "#9A6A00", "Low", "#0A7F0A", "#6B6B67" )', None),
    ("Latest Patch Month", f'FORMAT ( MAX ( {CAT}[PatchMonthStart] ), "MMM-yyyy" )', None),
    ("Data Source Label", f'"Data: " & SELECTEDVALUE ( {DEV}[DataSource], "Defender" )', None),
    ("Data As Of", f'"Devices seen up to " & FORMAT ( MAX ( {DEV}[LastSeen] ), "dd-MMM-yyyy HH:mm" )', None),
    ("Report Subtitle",
     f'[Data Source Label] & "  |  " & [Data As Of] & "  |  Latest Microsoft release: " & [Latest Patch Month]', None),
]
CATALOG_MEASURES = [
    ("Windows Versions Tracked", f"DISTINCTCOUNT ( {CAT}[OSName] )", "#,0"),
    ("Windows Versions Serviced", f"CALCULATE ( DISTINCTCOUNT ( {CAT}[OSName] ), {CAT}[OSStillServiced] = TRUE () )", "#,0"),
    ("Releases Tracked", f"COUNTROWS ( {CAT} )", "#,0"),
    ("CVEs Fixed", f"MAX ( {CAT}[CVECount] )", "#,0"),
    ("Latest Release CVEs",
     f"VAR m = MAX ( {CAT}[PatchMonthStart] ) RETURN CALCULATE ( MAX ( {CAT}[CVECount] ), {CAT}[PatchMonthStart] = m )", "#,0"),
    ("Latest Release Exploited",
     f"VAR m = MAX ( {CAT}[PatchMonthStart] ) RETURN CALCULATE ( MAX ( {CAT}[ExploitedCVECount] ), {CAT}[PatchMonthStart] = m )", "#,0"),
    ("Serviced Label", f'IF ( SELECTEDVALUE ( {CAT}[OSStillServiced] ), "Serviced", "End of support" )', None),
]


# --------------------------------------------------------------------------- Power Query

def kql_for_m() -> str:
    lines = []
    for line in (ROOT / "kql" / "DevicePatchLevel.kql").read_text(encoding="utf-8").splitlines():
        if line.lstrip().startswith("//"):
            continue
        line = re.sub(r"\s+//\s.*$", "", line).rstrip()
        if line:
            lines.append(line)
    return "\n".join(lines).replace('"', '""')


def m_value(value) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, dt.datetime):
        return f"#datetime({value.year},{value.month},{value.day},{value.hour},{value.minute},0)"
    if isinstance(value, dt.date):
        return f"#date({value.year},{value.month},{value.day})"
    return '"' + str(value).replace('"', '""') + '"'


def device_query(samples: list[dict]) -> str:
    names = [c for c, _, _ in DEVICE_COLUMNS if c not in DERIVED_DEVICE_COLUMNS]
    sample_rows = ",\n            ".join("{" + ", ".join(m_value(row[c]) for c in names) + "}" for row in samples)
    types = ", ".join(f'{{"{c}", {t}}}' for c, _, t in DEVICE_COLUMNS)
    column_list = ", ".join(f'"{c}"' for c in names)
    return f'''let
    // DataSource parameter: "Defender" = your tenant (Advanced Hunting API, organizational sign-in),
    // "Sample" = built-in example devices. Query text generated from kql/DevicePatchLevel.kql.
    AdvancedHuntingQuery = "{kql_for_m()}",
    FromDefender = () =>
        let
            Response = Json.Document(Web.Contents("https://api.securitycenter.microsoft.com", [
                RelativePath = "api/advancedqueries/run",
                Headers = [#"Content-Type" = "application/json"],
                Content = Json.FromValue([Query = AdvancedHuntingQuery])
            ])),
            Rows = Table.FromRecords(Response[Results], List.Transform(Response[Schema], each [Name]), MissingField.UseNull),
            LastSeenUtc = Table.TransformColumns(Rows, {{{{"LastSeen", each if _ = null then null else DateTimeZone.RemoveZone(DateTimeZone.From(_)), type nullable datetime}},
                                                       {{"PatchMonthStart", each if _ = null then null else Date.From(DateTimeZone.From(_)), type nullable date}}}})
        in
            LastSeenUtc,
    FromSample = () => #table({{{column_list}}}, {{
            {sample_rows}
        }}),
    Source = if DataSource = "Defender" then FromDefender() else FromSample(),
    AllColumns = Table.SelectColumns(Source, {{{column_list}}}, MissingField.UseNull),
    WithSource = Table.AddColumn(AllColumns, "DataSource", each DataSource, type text),
    WithRiskOrder = Table.AddColumn(WithSource, "RiskOrder", each
        if [RiskLevel] = "Low" then 1 else if [RiskLevel] = "Medium" then 2 else if [RiskLevel] = "High" then 3
        else if [RiskLevel] = "Critical" then 4 else 5, Int64.Type),
    Typed = Table.TransformColumnTypes(WithRiskOrder, {{{types}}})
in
    Typed'''


def catalog_query() -> str:
    types = ", ".join(f'{{"{c}", {t}}}' for c, _, t in CATALOG_COLUMNS)
    return f'''let
    // Public catalog maintained by GitHub Actions (anonymous access).
    Source = Csv.Document(
        Web.Contents("https://raw.githubusercontent.com", [RelativePath = "{CATALOG_URL_PATH}"]),
        [Delimiter = ",", Encoding = 65001, QuoteStyle = QuoteStyle.Csv]),
    Promoted = Table.PromoteHeaders(Source, [PromoteAllScalars = true]),
    Typed = Table.TransformColumnTypes(Promoted, {{{types}}}, "en-US")
in
    Typed'''


# --------------------------------------------------------------------------- sample devices

def sample_devices() -> list[dict]:
    """Realistic example devices built from the real catalog, classified exactly like the KQL."""
    rng = random.Random(42)
    with (ROOT / "data" / "Windows_Security_Releases.csv").open(encoding="utf-8") as handle:
        catalog = [r for r in csv.DictReader(handle) if r["Revision"]]
    by_os = {}
    for row in catalog:
        by_os.setdefault((row["Platform"], row["OSName"]), []).append(row)
    for rows in by_os.values():
        rows.sort(key=lambda r: int(r["ReleaseRank"]))

    plan = [  # (platform, OS, platform label, how many, max releases behind)
        ("Client", "Windows 11 Version 24H2", "Windows11", 26, 4), ("Client", "Windows 11 Version 25H2", "Windows11", 18, 2),
        ("Client", "Windows 11 Version 23H2", "Windows11", 10, 8), ("Client", "Windows 10 Version 22H2", "Windows10", 14, 14),
        ("Client", "Windows 10 Version 21H2", "Windows10", 4, 3), ("Client", "Windows 11 Version 22H2", "Windows11", 3, 2),
        ("Server", "Windows Server 2025", "WindowsServer2025", 8, 2), ("Server", "Windows Server 2022", "WindowsServer2022", 12, 6),
        ("Server", "Windows Server 2019", "WindowsServer2019", 9, 10), ("Server", "Windows Server 2016", "WindowsServer2016", 5, 12),
        ("Server", "Windows Server 2012 R2", "WindowsServer2012R2", 2, 3),
    ]
    groups = ["Finance", "HR", "Engineering", "Sales", "Datacenter", "DMZ"]
    now = dt.datetime(2026, 10, 22, 9, 0)
    devices = []
    for platform, os_name, os_platform, count, max_behind in plan:
        releases = by_os[(platform, os_name)]
        for _ in range(count):
            behind = min(int(rng.triangular(0, max_behind, 0)), len(releases) - 1)
            release = releases[behind]
            devices.append(classified(rng, len(devices), platform, os_platform, release, releases, groups, now))
    # Edge cases the dashboard must show
    devices.append(unverified(len(devices), "Windows11", "10.0.27950.1000", 27950, "Unverified version - OS build not in Microsoft security catalog", now))
    devices.append(unverified(len(devices), "WindowsServer2022", "20348", 20348, "Unverified version - build revision not reported", now))
    old = by_os[("Client", "Windows 10 Version 22H2")][-1]
    devices.append({**base(len(devices), "Windows10", "Client", 19045, "10.0.19045.1288", "Engineering", now),
                    "OSName": old["OSName"], "PatchMonth": f"Before {old['PatchMonth']}", "PatchMonthStart": None,
                    "InstalledSecurityKB": None, "PatchesBehind": int(old["ReleaseRank"]),
                    "CVEsMissed": int(old["CVEsReleasedSince"]) + int(old["CVECount"]),
                    "CriticalCVEsMissed": int(old["CriticalCVEsReleasedSince"]) + int(old["CriticalCVECount"]),
                    "ExploitedCVEsMissed": int(old["ExploitedCVEsReleasedSince"]) + int(old["ExploitedCVECount"]),
                    "LatestPatchMonth": old["OSLatestPatchMonth"], "LatestBuild": old["OSLatestFullBuild"],
                    "OSStillServiced": True, "VersionStatus": "Older than catalog history",
                    "PatchStatus": "6+ months behind", "PatchStatusOrder": 5, "RiskLevel": "Critical"})
    return devices


def base(i, os_platform, platform, build, full_build, group, now):
    return {"LastSeen": now - dt.timedelta(hours=(i * 7) % 300), "DeviceId": f"sample-{i:04d}",
            "DeviceName": f"SAMPLE-{'SRV' if platform == 'Server' else 'WS'}-{i:03d}",
            "MachineGroup": f"Sample - {group}", "ExposureLevel": ["Low", "Medium", "High"][i % 3],
            "OSPlatform": os_platform, "OSArchitecture": "x64", "DeviceOSBuild": full_build,
            "Platform": platform, "BuildNumber": build}


def classified(rng, i, platform, os_platform, release, releases, groups, now):
    behind = int(release["ReleaseRank"]) - 1
    serviced = release["OSStillServiced"] == "true"
    status = ("Unsupported OS" if not serviced else "Current" if behind == 0 else "1 month behind" if behind == 1
              else "2 months behind" if behind == 2 else "3-5 months behind" if behind <= 5 else "6+ months behind")
    order = ["Current", "1 month behind", "2 months behind", "3-5 months behind", "6+ months behind", "Unsupported OS"].index(status) + 1
    risk = "Critical" if not serviced or behind >= 3 else "High" if behind == 2 else "Medium" if behind == 1 else "Low"
    group = "Datacenter" if platform == "Server" and rng.random() < 0.7 else ("DMZ" if platform == "Server" else rng.choice(groups[:4]))
    preview = rng.random() < 0.15 and behind > 0  # some devices run a preview build after the release
    revision = int(release["Revision"]) + (rng.randint(1, 60) if preview else 0)
    full_build = ".".join(release["FullBuild"].split(".")[:3] + [str(revision)])
    return {**base(i, os_platform, platform, int(release["BuildNumber"]), full_build, group, now),
            "OSName": release["OSName"], "PatchMonth": release["PatchMonth"],
            "PatchMonthStart": dt.date.fromisoformat(release["PatchMonthStart"]), "InstalledSecurityKB": release["KB"],
            "PatchesBehind": behind, "CVEsMissed": int(release["CVEsReleasedSince"]),
            "CriticalCVEsMissed": int(release["CriticalCVEsReleasedSince"]),
            "ExploitedCVEsMissed": int(release["ExploitedCVEsReleasedSince"]),
            "LatestPatchMonth": release["OSLatestPatchMonth"], "LatestBuild": release["OSLatestFullBuild"],
            "OSStillServiced": serviced, "VersionStatus": "Verified", "PatchStatus": status,
            "PatchStatusOrder": order, "RiskLevel": risk}


def unverified(i, os_platform, full_build, build, version_status, now):
    platform = "Server" if "Server" in os_platform else "Client"
    return {**base(i, os_platform, platform, build, full_build, "Engineering", now),
            "OSName": f"{os_platform} ", "PatchMonth": "Unverified version", "PatchMonthStart": None,
            "InstalledSecurityKB": None, "PatchesBehind": None, "CVEsMissed": None, "CriticalCVEsMissed": None,
            "ExploitedCVEsMissed": None, "LatestPatchMonth": None, "LatestBuild": None, "OSStillServiced": None,
            "VersionStatus": version_status, "PatchStatus": "Unverified version", "PatchStatusOrder": 7,
            "RiskLevel": "Unknown"}


# --------------------------------------------------------------------------- semantic model

OS_SHORT_DAX = ('SUBSTITUTE ( SUBSTITUTE ( SUBSTITUTE ( SUBSTITUTE ( [OSName], "Windows Server, Version ", "Server " ), '
                '"Windows Server ", "Server " ), "Windows ", "Win " ), " Version ", " " )')


def table(name, columns, query, measures=(), sort_by=None, calculated=()):
    sort_by = sort_by or {}
    calculated = [("OS", "string", OS_SHORT_DAX)] + list(calculated)
    return {
        "name": name,
        "columns": [{"type": "calculated", "name": n, "dataType": t, "expression": e, "summarizeBy": "none"}
                    for n, t, e in calculated] + [{
            "name": c, "dataType": t, "sourceColumn": c,
            "summarizeBy": "none",
            **({"formatString": "dd-MMM-yyyy" if c in ("PatchMonthStart", "ReleaseDate") else "dd-MMM-yyyy HH:mm"} if t == "dateTime" else {}),
            **({"sortByColumn": sort_by[c]} if c in sort_by else {}),
        } for c, t, _ in columns],
        "partitions": [{"name": name, "mode": "import", "source": {"type": "m", "expression": query.splitlines()}}],
        "measures": [{"name": n, "expression": e, **({"formatString": f} if f else {})} for n, e, f in measures],
    }


def semantic_model() -> dict:
    return {
        "compatibilityLevel": 1567,
        "model": {
            "culture": "en-US",
            "defaultPowerBIDataSourceVersion": "powerBI_V3",
            "sourceQueryCulture": "en-US",
            "dataAccessOptions": {"legacyRedirects": True, "returnErrorValuesAsNull": True},
            "tables": [
                table(DEV, DEVICE_COLUMNS, device_query(sample_devices()), MEASURES,
                      {"PatchStatus": "PatchStatusOrder", "PatchMonth": "PatchMonthStart", "RiskLevel": "RiskOrder"},
                      ),
                table(CAT, CATALOG_COLUMNS, catalog_query(), CATALOG_MEASURES, {"PatchMonth": "PatchMonthStart"}),
            ],
            "expressions": [{
                "name": "DataSource", "kind": "m",
                "expression": '"Sample" meta [IsParameterQuery=true, List={"Defender", "Sample"}, '
                              'DefaultValue="Defender", Type="Text", IsParameterQueryRequired=true]',
            }],
            "annotations": [
                {"name": "PBI_QueryOrder", "value": json.dumps(["DataSource", DEV, CAT])},
                {"name": "__PBI_TimeIntelligenceEnabled", "value": "0"},
            ],
        },
    }


# --------------------------------------------------------------------------- report (PBIR)

THEME_NAME = "PatchIntelligence"
PAGE_W, PAGE_H = 1280, 720
RAIL_W = 196
X0, GAP = RAIL_W + 16, 12          # content starts after the navigation rail
CONTENT_W = PAGE_W - X0 - 16


def theme() -> dict:
    """Custom theme: light canvas, white rounded cards with a soft shadow, quiet axes."""
    solid = lambda c: {"solid": {"color": c}}
    return {
        "name": THEME_NAME,
        "dataColors": ["#2A78D6", "#EB6834", "#1BAF7A", "#EDA100", "#E87BA4", "#008300", "#6250D6", "#E34948"],
        "foreground": UI["ink"], "foregroundNeutralSecondary": UI["ink2"], "foregroundNeutralTertiary": UI["muted"],
        "background": UI["card"], "backgroundLight": UI["canvas"], "backgroundNeutral": UI["border"],
        "tableAccent": UI["blue"], "good": "#0CA30C", "neutral": "#FAB219", "bad": "#D03B3B",
        "maximum": UI["blue"], "center": UI["blue_mid"], "minimum": UI["blue_light"],
        "textClasses": {
            "callout": {"fontSize": 26, "fontFace": "Segoe UI Semibold", "color": UI["ink"]},
            "title": {"fontSize": 11, "fontFace": "Segoe UI Semibold", "color": UI["ink"]},
            "header": {"fontSize": 10, "fontFace": "Segoe UI Semibold", "color": UI["ink2"]},
            "label": {"fontSize": 9, "fontFace": "Segoe UI", "color": UI["ink2"]},
        },
        "visualStyles": {
            "*": {"*": {
                "background": [{"show": True, "color": solid(UI["card"]), "transparency": 0}],
                "border": [{"show": True, "color": solid(UI["border"]), "radius": 12}],
                "dropShadow": [{"show": True, "color": solid("#0E1726"), "position": "Outer", "preset": "Custom",
                                "shadowSpread": 0, "shadowBlur": 14, "angle": 90, "shadowDistance": 3, "transparency": 92}],
                "padding": [{"top": 10, "bottom": 10, "left": 14, "right": 14}],
                "title": [{"show": True, "fontColor": solid(UI["ink"]), "fontSize": 11,
                           "fontFamily": "Segoe UI Semibold", "alignment": "left"}],
                "subTitle": [{"show": True, "fontColor": solid(UI["muted"]), "fontSize": 9, "fontFamily": "Segoe UI"}],
                "categoryAxis": [{"gridlineShow": False, "fontSize": 9, "labelColor": solid(UI["ink2"]),
                                  "showAxisTitle": False}],
                "valueAxis": [{"gridlineShow": True, "gridlineColor": solid("#ECEEF2"), "gridlineStyle": "dotted",
                               "fontSize": 9, "labelColor": solid(UI["muted"]), "showAxisTitle": False}],
                "legend": [{"show": True, "position": "Top", "fontSize": 9, "labelColor": solid(UI["ink2"]),
                            "showTitle": False}],
                "labels": [{"fontSize": 9, "color": solid(UI["ink2"])}],
            }},
            "page": {"*": {
                "background": [{"color": solid(UI["canvas"]), "transparency": 0}],
                "outspace": [{"color": solid("#E9ECF1"), "transparency": 0}],
            }},
            "card": {"*": {
                "labels": [{"color": solid(UI["ink"]), "fontSize": 26, "fontFamily": "Segoe UI Semibold"}],
                "categoryLabels": [{"show": False}],
                "title": [{"fontSize": 10, "fontColor": solid(UI["ink2"]), "fontFamily": "Segoe UI"}],
            }},
            "textbox": {"*": {"background": [{"show": False}], "border": [{"show": False}],
                              "dropShadow": [{"show": False}], "padding": [{"top": 0, "bottom": 0, "left": 0, "right": 0}]}},
            "actionButton": {"*": {"background": [{"show": False}], "border": [{"show": False}],
                                   "dropShadow": [{"show": False}], "padding": [{"top": 0, "bottom": 0, "left": 0, "right": 0}]}},
            "slicer": {"*": {
                "header": [{"show": False}],
                "items": [{"fontColor": solid(UI["ink"]), "fontSize": 10, "background": solid(UI["card"])}],
                "title": [{"fontSize": 9, "fontColor": solid(UI["muted"]), "fontFamily": "Segoe UI"}],
                "padding": [{"top": 4, "bottom": 6, "left": 10, "right": 10}],
            }},
            "tableEx": {"*": {
                "grid": [{"gridVertical": False, "gridHorizontal": True, "gridHorizontalColor": solid("#EEF0F4"),
                          "rowPadding": 5, "outlineColor": solid(UI["border"])}],
                "columnHeaders": [{"fontColor": solid(UI["ink2"]), "backColor": solid(UI["card"]),
                                   "fontFamily": "Segoe UI Semibold", "fontSize": 9, "outline": "BottomOnly"}],
                "values": [{"fontColorPrimary": solid(UI["ink"]), "backColorPrimary": solid(UI["card"]),
                            "fontColorSecondary": solid(UI["ink"]), "backColorSecondary": solid("#FAFBFC"),
                            "fontSize": 9}],
            }},
            "pivotTable": {"*": {
                "grid": [{"gridVertical": False, "gridHorizontalColor": solid("#EEF0F4"), "rowPadding": 6}],
                "columnHeaders": [{"fontColor": solid(UI["ink2"]), "backColor": solid(UI["card"]),
                                   "fontFamily": "Segoe UI Semibold", "fontSize": 9}],
                "rowHeaders": [{"fontColor": solid(UI["ink"]), "backColor": solid(UI["card"]), "fontSize": 9}],
                "values": [{"fontSize": 10, "backColorPrimary": solid(UI["card"]), "backColorSecondary": solid(UI["card"])}],
            }},
        },
    }


def col(entity, prop):
    return {"Column": {"Expression": {"SourceRef": {"Entity": entity}}, "Property": prop}}


def measure(prop, entity=DEV):
    return {"Measure": {"Expression": {"SourceRef": {"Entity": entity}}, "Property": prop}}


def agg(field, function=0):  # 0 = Sum, 1 = Average, 4 = Max
    return {"Aggregation": {"Expression": field, "Function": function}}


DISPLAY_NAMES = {
    "DeviceName": "Device", "MachineGroup": "Device group", "OSName": "OS version", "DeviceOSBuild": "Installed build",
    "PatchMonth": "Patch month", "InstalledSecurityKB": "Installed KB", "PatchesBehind": "Releases behind",
    "CVEsMissed": "CVEs missed", "CriticalCVEsMissed": "Critical missed", "ExploitedCVEsMissed": "Exploited missed",
    "LatestBuild": "Latest build", "RiskLevel": "Risk", "LastSeen": "Last seen", "PatchStatus": "Patch status",
    "OSLatestPatchMonth": "Latest release", "OSLatestFullBuild": "Latest build", "KB": "KB", "FullBuild": "Build",
    "CVECount": "CVEs fixed", "CriticalCVECount": "Critical", "ExploitedCVECount": "Exploited",
    "ReleaseDate": "Released", "OSStillServiced": "Serviced", "Platform": "Platform",
    "Devices": "Devices", "% Current": "% patched", "Avg Patches Behind": "Avg. behind",
    "Exploited CVE Exposures": "Exploited CVE gaps", "CVEs Fixed": "CVEs fixed", "Serviced Label": "Support",
    "ExposureLevel": "Exposure", "LatestPatchMonth": "Latest release", "OS": "OS version",
}


def projection(field):
    inner = field["Aggregation"]["Expression"] if "Aggregation" in field else field
    kind = "Measure" if "Measure" in inner else "Column"
    entity = inner[kind]["Expression"]["SourceRef"]["Entity"]
    prop = inner[kind]["Property"]
    ref = f"{entity}.{prop}"
    if "Aggregation" in field:
        ref = f"{['Sum', 'Avg', 'Count', 'Min', 'Max'][field['Aggregation']['Function']]}({ref})"
    result = {"field": field, "queryRef": ref, "nativeQueryRef": prop}
    if prop in DISPLAY_NAMES:
        result["displayName"] = DISPLAY_NAMES[prop]
    return result


def lit(value):
    if isinstance(value, bool):
        return {"expr": {"Literal": {"Value": "true" if value else "false"}}}
    if isinstance(value, (int, float)):
        return {"expr": {"Literal": {"Value": f"{value}D"}}}
    return {"expr": {"Literal": {"Value": "'" + value.replace("'", "''") + "'"}}}


def color(hex_value):
    return {"solid": {"color": lit(hex_value)}}


def props(**kwargs):
    return [{"properties": {k: v for k, v in kwargs.items()}}]


class Page:
    def __init__(self, name, display, nav_label, description):
        self.name, self.display, self.nav_label, self.description = name, display, nav_label, description
        self.visuals = []

    def add(self, visual_type, x, y, w, h, roles=None, title=None, subtitle=None, objects=None, sort=None,
            filters=None, container=None, sync=None):
        visual = {"visualType": visual_type, "drillFilterOtherVisuals": True}
        if roles:
            visual["query"] = {"queryState": {role: {"projections": [projection(f) for f in fields]}
                                              for role, fields in roles.items()}}
            if sort:
                field, direction = sort
                visual["query"]["sortDefinition"] = {"sort": [{"field": field, "direction": direction}],
                                                     "isDefaultSort": True}
        if visual_type == "tableEx":
            objects = {**(objects or {}), "total": props(totals=lit(False))}
        if objects:
            visual["objects"] = objects
        vco = dict(container or {})
        if title:
            vco["title"] = props(show=lit(True), text=lit(title))
        if subtitle:
            vco["subTitle"] = props(show=lit(True), text=lit(subtitle))
        if vco:
            visual["visualContainerObjects"] = vco
        if sync:
            visual["syncGroup"] = {"groupName": sync, "fieldChanges": True, "filterChanges": True}
        container_json = {
            "$schema": f"{SCHEMA}/report/definition/visualContainer/2.10.0/schema.json",
            "name": f"{self.name}_{len(self.visuals):02d}",
            "position": {"x": round(x, 1), "y": round(y, 1), "z": len(self.visuals) * 1000,
                         "width": round(w, 1), "height": round(h, 1), "tabOrder": len(self.visuals) * 1000},
            "visual": visual,
        }
        if filters:
            container_json["filterConfig"] = {"filters": filters}
        self.visuals.append(container_json)


def plain(background=None, radius=0, shadow=False):
    """Container formatting for chrome elements (rail, header text): no card look."""
    vco = {"border": props(show=lit(False)), "dropShadow": props(show=lit(shadow)),
           "padding": props(top=lit(0), bottom=lit(0), left=lit(0), right=lit(0))}
    vco["background"] = (props(show=lit(True), color=color(background), transparency=lit(0)) if background
                         else props(show=lit(False)))
    if radius:
        vco["border"] = props(show=lit(False), radius=lit(radius))
    return vco


def text(page, x, y, w, h, runs, background=None):
    """runs: list of paragraphs, each a list of (text, size, color, weight)."""
    paragraphs = [{"textRuns": [{"value": t, "textStyle": {
        "fontSize": f"{size}pt", "color": c, "fontFamily": "Segoe UI Semibold" if bold else "Segoe UI"}}
        for t, size, c, bold in para]} for para in runs]
    page.add("textbox", x, y, w, h, objects={"general": props(paragraphs=paragraphs)}, container=plain(background))


def in_filter(name, entity, prop, values):
    return {
        "name": name, "field": col(entity, prop), "type": "Categorical",
        "filter": {"Version": 2, "From": [{"Name": "t", "Entity": entity, "Type": 0}],
                   "Where": [{"Condition": {"In": {
                       "Expressions": [{"Column": {"Expression": {"SourceRef": {"Source": "t"}}, "Property": prop}}],
                       "Values": [[{"Literal": lit(v)["expr"]["Literal"]}] for v in values]}}}]},
    }


def category_colors(entity, prop, colors, key="fill"):
    return [{"properties": {key: color(c)},
             "selector": {"data": [{"scopeId": {"Comparison": {
                 "ComparisonKind": 0, "Left": col(entity, prop), "Right": {"Literal": lit(v)["expr"]["Literal"]}}}}]}}
            for v, c in colors.items()]


def series_color(hex_value):
    return [{"properties": {"fill": color(hex_value)}}]


def risk_font_color(column="RiskLevel"):
    """Conditional font colour (by field value) for the Risk column of a table."""
    return [{"properties": {"fontColor": {"solid": {"color": {"expr": measure("Risk Color")}}}},
             "selector": {"data": [{"dataViewWildcard": {"matchingOption": 1}}], "metadata": f"{DEV}.{column}"}}]


def heat(measure_name, entity=DEV, low="#FFFFFF", high=UI["blue_mid"]):
    """Sequential (one-hue) background gradient for matrix cells."""
    return [{"properties": {"backColor": {"solid": {"color": {"expr": {"FillRule": {
        "Input": measure(measure_name, entity),
        "FillRule": {"linearGradient2": {"min": {"color": lit(low)["expr"]}, "max": {"color": lit(high)["expr"]},
                                         "nullColoringStrategy": {"strategy": lit("asZero")["expr"]}}}}}}}}},
             "selector": {"data": [{"dataViewWildcard": {"matchingOption": 1}}], "metadata": f"{entity}.{measure_name}"}}]


# ---------------------------------------------------------------------- shared chrome

def chrome(page: Page, pages: list[Page], filters=True):
    """Navigation rail, page header and (optionally) the synced filter row."""
    page.add("textbox", 0, 0, RAIL_W, PAGE_H, objects={"general": props(paragraphs=[{"textRuns": [{"value": " "}]}])},
             container=plain(UI["rail"]))
    text(page, 20, 22, RAIL_W - 32, 52, [
        [("PATCH", 15, "#FFFFFF", True), ("INTEL", 15, UI["blue_mid"], True)],
        [("Windows · Defender for Endpoint", 8, UI["rail_text"], False)]])
    for i, target in enumerate(pages):
        y = 100 + i * 44
        active = target is page
        if active:
            page.add("textbox", 12, y, RAIL_W - 24, 36, objects={"general": props(paragraphs=[{"textRuns": [{"value": " "}]}])},
                     container=plain(UI["rail_active"], radius=8))
            page.add("textbox", 12, y + 8, 4, 20, objects={"general": props(paragraphs=[{"textRuns": [{"value": " "}]}])},
                     container=plain(UI["accent"], radius=2))
        default, hover = {"selector": {"id": "default"}}, {"selector": {"id": "hover"}}
        # Button "show" switches are state-less; text/colours are set per state (default / hover).
        page.add("actionButton", 12, y, RAIL_W - 24, 36, objects={
            "icon": [{"properties": {"show": lit(False)}},
                     {"properties": {"shapeType": lit("blank")}, **default}],
            "text": [{"properties": {"show": lit(True)}},
                     {"properties": {"text": lit(target.nav_label),
                                     "fontColor": color("#FFFFFF" if active else UI["rail_text"]), "fontSize": lit(10),
                                     "fontFamily": lit("Segoe UI Semibold" if active else "Segoe UI"),
                                     "horizontalAlignment": lit("left"), "leftMargin": lit(20)}, **default},
                     {"properties": {"text": lit(target.nav_label), "fontColor": color("#FFFFFF")}, **hover}],
            "fill": [{"properties": {"show": lit(True)}},
                     {"properties": {"fillColor": color(UI["rail"]), "transparency": lit(100)}, **default},
                     {"properties": {"fillColor": color(UI["rail_active"]), "transparency": lit(0)}, **hover}],
            "outline": [{"properties": {"show": lit(False)}}],
        }, container={**plain(), "visualLink": props(show=lit(True), type=lit("PageNavigation"),
                                                      navigationSection=lit(target.name))})
    page.add("card", 12, PAGE_H - 92, RAIL_W - 24, 34, {"Values": [measure("Data Source Label")]},
             objects={"labels": props(fontSize=lit(10), color=color("#FFFFFF"), fontFamily=lit("Segoe UI Semibold")),
                      "categoryLabels": props(show=lit(False))}, container=plain())
    page.add("card", 12, PAGE_H - 62, RAIL_W - 24, 44, {"Values": [measure("Data As Of")]},
             objects={"labels": props(fontSize=lit(8), color=color(UI["rail_text"]), fontFamily=lit("Segoe UI")),
                      "categoryLabels": props(show=lit(False)), "wordWrap": props(show=lit(True))},
             container=plain())
    text(page, X0, 14, 520, 56, [[(page.display, 18, UI["ink"], True)], [(page.description, 9, UI["ink2"], False)]])
    if filters:
        fields = [("RiskLevel", "Risk level"), ("Platform", "Platform"), ("MachineGroup", "Device group"), ("OS", "OS version")]
        w = 122
        for i, (prop, label) in enumerate(fields):
            page.add("slicer", PAGE_W - 16 - (len(fields) - i) * (w + 8) + 8, 10, w, 62, {"Values": [col(DEV, prop)]},
                     title=label, objects={"data": props(mode=lit("Dropdown"))}, sync=f"sync_{prop}",
                     container={"padding": props(top=lit(2), bottom=lit(4), left=lit(8), right=lit(8))})


def kpi(page, x, y, w, h, measure_name, label, note, value_color=None, entity=DEV):
    labels = {"fontSize": lit(24), "fontFamily": lit("Segoe UI Semibold"), "labelDisplayUnits": lit(1)}
    if value_color:
        labels["color"] = color(value_color)
    page.add("card", x, y, w, h, {"Values": [measure(measure_name, entity)]}, title=label, subtitle=note,
             objects={"labels": props(**labels), "categoryLabels": props(show=lit(False))})


def kpi_row(page, y, items, h=96):
    w = (CONTENT_W - GAP * (len(items) - 1)) / len(items)
    for i, item in enumerate(items):
        kpi(page, X0 + i * (w + GAP), y, w, h, *item)


# ---------------------------------------------------------------------- pages

def build_pages() -> list[Page]:
    pages = [
        Page("overview", "Patch risk overview", "Overview", "How current is the Windows estate, and where is the risk?"),
        Page("risk", "Risk & exposure", "Risk & exposure", "Missing security fixes, critical and exploited CVEs, and who carries them"),
        Page("os", "OS landscape", "OS landscape", "Windows versions in use, their patch level and support status"),
        Page("devices", "Device explorer", "Device explorer", "Every device with its installed build, patch month and risk"),
        Page("attention", "Needs attention", "Needs attention", "Critical and High risk devices – the hand-off list for the patching team"),
        Page("catalog", "Windows release catalog", "Release catalog", "Microsoft security releases per Windows version, refreshed automatically from MSRC"),
        Page("guide", "How to read this report", "How to read", "Definitions, data sources and how to switch to your tenant"),
    ]
    by = {p.name: p for p in pages}
    for p in pages:
        chrome(p, pages, filters=p.name not in ("catalog", "guide"))

    top = 84
    # ---------------- Overview
    p = by["overview"]
    kpi_row(p, top, [
        ("Devices", "Devices", "Seen in last 30 days"),
        ("% Current", "Fully patched", "On latest release", "#0A7F0A"),
        ("Devices Critical Risk", "Critical risk", "3+ behind or unsupported", "#B42323"),
        ("Avg Patches Behind", "Avg. releases behind", "Verified devices"),
        ("Devices Missing Exploited CVEs", "Exploited CVE gaps", "Missing an exploited fix", "#B42323"),
        ("Devices Unverified", "Unverified", "Build not in catalog", UI["muted"]),
    ])
    row2 = top + 96 + GAP
    p.add("gauge", X0, row2, 300, 250,
          {"Y": [measure("% Current")], "MinValue": [measure("Gauge Max")], "MaxValue": [measure("Gauge Max")],
           "TargetValue": [measure("Compliance Target")]},
          title="Patch compliance", subtitle="Fully patched devices vs 95% target",
          objects={"dataPoint": props(fill=color("#0CA30C"), target=color(UI["ink"])),
                   "calloutValue": props(fontSize=lit(26), color=color(UI["ink"])),
                   "axis": props(min=lit(0), max=lit(1))})
    p.visuals[-1]["visual"]["query"]["queryState"].pop("MinValue")
    p.add("donutChart", X0 + 300 + GAP, row2, 330, 250,
          {"Category": [col(DEV, "PatchStatus")], "Y": [measure("Devices")]},
          title="Patch status", subtitle="Devices by releases behind",
          objects={"dataPoint": category_colors(DEV, "PatchStatus", STATUS_COLORS),
                   "legend": props(show=lit(True), position=lit("Right")),
                   "labels": props(show=lit(False)),
                   "slices": props(innerRadiusRatio=lit(68))})
    x3 = X0 + 300 + GAP + 330 + GAP
    p.add("hundredPercentStackedBarChart", x3, row2, PAGE_W - 16 - x3, 250,
          {"Category": [col(DEV, "Platform")], "Y": [measure("Devices")], "Series": [col(DEV, "PatchStatus")]},
          title="Clients vs servers", subtitle="Share of devices by patch status",
          objects={"dataPoint": category_colors(DEV, "PatchStatus", STATUS_COLORS),
                   "legend": props(show=lit(False)), "labels": props(show=lit(True), fontSize=lit(9))})
    row3 = row2 + 250 + GAP
    p.add("clusteredColumnChart", X0, row3, 620, PAGE_H - 16 - row3,
          {"Category": [col(DEV, "PatchMonth")], "Y": [measure("Devices")]},
          title="Installed patch month", subtitle="Devices by the newest security release they contain (MMM-YYYY)",
          sort=(col(DEV, "PatchMonth"), "Ascending"),
          objects={"dataPoint": series_color(UI["blue"]), "labels": props(show=lit(True), fontSize=lit(8)),
                   "valueAxis": props(show=lit(False), gridlineShow=lit(False))})
    p.add("tableEx", X0 + 620 + GAP, row3, PAGE_W - 16 - (X0 + 620 + GAP), PAGE_H - 16 - row3,
          {"Values": [col(DEV, c) for c in ("DeviceName", "OS", "PatchMonth", "PatchesBehind", "RiskLevel")]},
          title="Furthest behind", sort=(col(DEV, "PatchesBehind"), "Descending"),
          objects={"values": risk_font_color()})

    # ---------------- Risk & exposure
    p = by["risk"]
    kpi_row(p, top, [
        ("Devices 3+ Behind", "3+ releases behind", "Devices", "#B42323"),
        ("CVE Exposures", "CVE gaps", "Device x CVE pairs"),
        ("Critical CVE Exposures", "Critical CVE gaps", "Critical severity", "#B42323"),
        ("Exploited CVE Exposures", "Exploited CVE gaps", "Exploited in the wild", "#B42323"),
        ("Devices Unsupported OS", "Unsupported OS", "Out of support", "#6250D6"),
    ])
    row2 = top + 96 + GAP
    half = (CONTENT_W - GAP) / 2
    p.add("barChart", X0, row2, half, 250,
          {"Category": [col(DEV, "OS")], "Y": [measure("Exploited CVE Exposures")]},
          title="Exploited CVE gaps by OS version", subtitle="Missing fixes for actively exploited vulnerabilities",
          sort=(measure("Exploited CVE Exposures"), "Descending"),
          objects={"dataPoint": series_color(UI["blue"]), "labels": props(show=lit(True), fontSize=lit(9)),
                   "valueAxis": props(show=lit(False))})
    p.add("scatterChart", X0 + half + GAP, row2, half, 250,
          {"Category": [col(DEV, "DeviceName")], "X": [agg(col(DEV, "PatchesBehind"))],
           "Y": [agg(col(DEV, "CriticalCVEsMissed"))], "Series": [col(DEV, "RiskLevel")]},
          title="Releases behind vs critical CVEs missed", subtitle="One dot per device, coloured by risk",
          objects={"dataPoint": category_colors(DEV, "RiskLevel", RISK_COLORS),
                   "bubbles": props(bubbleSize=lit(-6)), "legend": props(show=lit(True), position=lit("Top"))})
    row3 = row2 + 250 + GAP
    p.add("pivotTable", X0, row3, half, PAGE_H - 16 - row3,
          {"Rows": [col(DEV, "MachineGroup")], "Columns": [col(DEV, "RiskLevel")], "Values": [measure("Devices")]},
          title="Risk heatmap", subtitle="Devices per device group and risk level (darker = more)",
          objects={"values": heat("Devices"), "subTotals": props(rowSubtotals=lit(False), columnSubtotals=lit(False))})
    p.add("tableEx", X0 + half + GAP, row3, half, PAGE_H - 16 - row3,
          {"Values": [col(DEV, c) for c in ("DeviceName", "OS", "ExploitedCVEsMissed", "CriticalCVEsMissed", "RiskLevel")]},
          title="Largest exploited CVE gaps", sort=(col(DEV, "ExploitedCVEsMissed"), "Descending"),
          objects={"values": risk_font_color()})

    # ---------------- OS landscape
    p = by["os"]
    kpi_row(p, top, [
        ("% Current Clients", "Clients fully patched", "Windows 10 / 11", "#0A7F0A"),
        ("% Current Servers", "Servers fully patched", "Windows Server", "#0A7F0A"),
        ("Devices Unsupported OS", "Unsupported OS", "Out of support", "#6250D6"),
        ("Latest Patch Month", "Latest Microsoft release", "Newest Patch Tuesday"),
    ])
    row2 = top + 96 + GAP
    p.add("treemap", X0, row2, 420, PAGE_H - 16 - row2,
          {"Group": [col(DEV, "Platform")], "Details": [col(DEV, "OS")], "Values": [measure("Devices")]},
          title="Windows estate", subtitle="Devices by platform and OS version",
          objects={"labels": props(show=lit(True), fontSize=lit(9)), "categoryLabels": props(show=lit(True), fontSize=lit(9))})
    p.add("hundredPercentStackedBarChart", X0 + 420 + GAP, row2, CONTENT_W - 420 - GAP, 286,
          {"Category": [col(DEV, "OS")], "Y": [measure("Devices")], "Series": [col(DEV, "PatchStatus")]},
          title="Patch status by OS version", subtitle="Share of devices in each status",
          objects={"dataPoint": category_colors(DEV, "PatchStatus", STATUS_COLORS), "legend": props(show=lit(True), position=lit("Top"))})
    row3 = row2 + 286 + GAP
    p.add("tableEx", X0 + 420 + GAP, row3, CONTENT_W - 420 - GAP, PAGE_H - 16 - row3,
          {"Values": [col(DEV, "OSName"), measure("Devices"), measure("% Current"), measure("Avg Patches Behind"),
                      col(DEV, "LatestPatchMonth"), col(DEV, "LatestBuild")]},
          title="OS version summary", sort=(measure("Devices"), "Descending"))

    # ---------------- Device explorer
    p = by["devices"]
    p.add("slicer", X0, top, 260, 62, {"Values": [col(DEV, "DeviceName")]}, title="Find a device",
          objects={"data": props(mode=lit("Dropdown"))})
    p.add("slicer", X0 + 260 + GAP, top, 260, 62, {"Values": [col(DEV, "PatchStatus")]}, title="Patch status",
          objects={"data": props(mode=lit("Dropdown"))})
    p.add("slicer", X0 + 2 * (260 + GAP), top, 260, 62, {"Values": [col(DEV, "VersionStatus")]}, title="Version status",
          objects={"data": props(mode=lit("Dropdown"))})
    p.add("tableEx", X0, top + 62 + GAP, CONTENT_W, PAGE_H - 16 - (top + 62 + GAP),
          {"Values": [col(DEV, c) for c in ("DeviceName", "MachineGroup", "OSName", "DeviceOSBuild", "PatchMonth",
                                            "InstalledSecurityKB", "PatchesBehind", "CVEsMissed", "ExploitedCVEsMissed",
                                            "LatestBuild", "RiskLevel", "ExposureLevel", "LastSeen")]},
          title="All devices", subtitle="Sorted by releases behind – use the filters above to narrow down",
          sort=(col(DEV, "PatchesBehind"), "Descending"), objects={"values": risk_font_color()})

    # ---------------- Needs attention
    p = by["attention"]
    kpi_row(p, top, [
        ("Devices Critical Risk", "Critical risk devices", "Patch these first", "#B42323"),
        ("Devices Missing Exploited CVEs", "Missing exploited fixes", "Highest attack likelihood", "#B42323"),
        ("Avg Patches Behind", "Avg. releases behind", "Critical + High"),
    ])
    row2 = top + 96 + GAP
    p.add("tableEx", X0, row2, CONTENT_W, PAGE_H - 16 - row2,
          {"Values": [col(DEV, c) for c in ("DeviceName", "MachineGroup", "OSName", "DeviceOSBuild", "PatchMonth",
                                            "InstalledSecurityKB", "PatchesBehind", "CriticalCVEsMissed",
                                            "ExploitedCVEsMissed", "LatestBuild", "RiskLevel", "LastSeen")]},
          title="Critical and High risk devices", subtitle="Export via ‘…’ > Export data for the patching team",
          sort=(col(DEV, "PatchesBehind"), "Descending"), objects={"values": risk_font_color()},
          filters=[in_filter("riskFilter", DEV, "RiskLevel", ["Critical", "High"])])
    for v in p.visuals:  # the KPIs on this page count only Critical/High devices as well
        if v["visual"]["visualType"] == "card" and v["position"]["y"] == top:
            v["filterConfig"] = {"filters": [in_filter("riskFilter", DEV, "RiskLevel", ["Critical", "High"])]}

    # ---------------- Release catalog
    p = by["catalog"]
    p.add("slicer", PAGE_W - 16 - 300, 10, 300, 62, {"Values": [col(CAT, "OS")]}, title="Windows version",
          objects={"data": props(mode=lit("Dropdown"))},
          container={"padding": props(top=lit(2), bottom=lit(4), left=lit(8), right=lit(8))})
    kpi_row(p, top, [
        ("Latest Patch Month", "Latest Patch Tuesday", "From Microsoft MSRC"),
        ("Windows Versions Serviced", "Versions still serviced", "Got the latest release", "#0A7F0A", CAT),
        ("Windows Versions Tracked", "Versions tracked", "Client and server", None, CAT),
        ("Latest Release CVEs", "CVEs fixed – latest release", "Largest update", None, CAT),
        ("Releases Tracked", "Releases in catalog", "Since Apr-2016", None, CAT),
    ])
    row2 = top + 96 + GAP
    p.add("areaChart", X0, row2, CONTENT_W, 250,
          {"Category": [col(CAT, "PatchMonthStart")], "Y": [measure("CVEs Fixed", CAT)]},
          title="CVEs fixed per Patch Tuesday", subtitle="Largest Windows update each month – pick a version above to see one OS",
          objects={"dataPoint": series_color(UI["blue"]), "lineStyles": props(strokeWidth=lit(2)),
                   "categoryAxis": props(axisType=lit("Scalar"))})
    row3 = row2 + 250 + GAP
    p.add("tableEx", X0, row3, CONTENT_W, PAGE_H - 16 - row3,
          {"Values": [col(CAT, c) for c in ("OSName", "Platform", "OSLatestPatchMonth", "OSLatestFullBuild", "KB", "CVECount")]
                     + [measure("Serviced Label", CAT)]},
          title="Latest release per Windows version", sort=(col(CAT, "OSName"), "Ascending"),
          filters=[in_filter("latestOnly", CAT, "IsLatestForOS", [True])])

    # ---------------- Guide
    p = by["guide"]
    col_w = (CONTENT_W - 2 * GAP) / 3
    blocks = [
        ("Patch status", [
            ("Current", "On the newest security release for its Windows version."),
            ("1 / 2 months behind", "Missing the latest one or two monthly security releases."),
            ("3-5 / 6+ months behind", "Missing three or more releases – high exposure."),
            ("Unsupported OS", "The Windows version no longer receives security releases."),
            ("Unverified version", "Build not found in Microsoft's catalog (preview/insider) or no build revision reported."),
        ]),
        ("Risk level", [
            ("Low", "Current."), ("Medium", "1 release behind."), ("High", "2 releases behind."),
            ("Critical", "3+ releases behind, or an unsupported OS."), ("Unknown", "Unverified version."),
            ("Patch month", "The newest Patch Tuesday (MMM-YYYY) whose build the device contains; preview and out-of-band builds count as the month they include."),
        ]),
        ("Data & refresh", [
            ("Catalog", "Microsoft MSRC security update API, rebuilt by GitHub Actions after every Patch Tuesday (repo jaydxt/Windows_Release_History)."),
            ("Devices", "Defender for Endpoint Advanced Hunting (DeviceInfo + Vulnerability Management), devices seen in the last 30 days."),
            ("Switch to your tenant", "Home > Transform data > Edit parameters > DataSource = Defender, then Refresh and sign in with your work account (read-only)."),
            ("CVE gaps", "CVE fixes released after the device's patch month, summed over devices."),
        ]),
    ]
    for i, (heading, items) in enumerate(blocks):
        x = X0 + i * (col_w + GAP)
        runs = [[(heading, 13, UI["ink"], True)], [(" ", 6, UI["ink"], False)]]
        for term, desc in items:
            runs.append([(term, 10, UI["blue"], True)])
            runs.append([(desc, 9, UI["ink2"], False)])
            runs.append([(" ", 5, UI["ink"], False)])
        p.add("textbox", x, top, col_w, PAGE_H - 16 - top,
              objects={"general": props(paragraphs=[{"textRuns": [{"value": t, "textStyle": {
                  "fontSize": f"{size}pt", "color": c, "fontFamily": "Segoe UI Semibold" if b else "Segoe UI"}}
                  for t, size, c, b in para]} for para in runs])},
              container={"background": props(show=lit(True), color=color(UI["card"]), transparency=lit(0)),
                         "border": props(show=lit(True), color=color(UI["border"]), radius=lit(12)),
                         "dropShadow": props(show=lit(True)),
                         "padding": props(top=lit(16), bottom=lit(16), left=lit(18), right=lit(18))})
    return pages


# --------------------------------------------------------------------------- write

def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--theme-file", type=Path, required=True,
                        help=f"{THEME}.json from Power BI Desktop's ...\\sharedresources\\BaseThemes folder")
    args = parser.parse_args()

    if OUT.exists():
        shutil.rmtree(OUT)
    model_dir = OUT / f"{NAME}.SemanticModel"
    report_dir = OUT / f"{NAME}.Report"

    write_json(OUT / f"{NAME}.pbip", {
        "$schema": "https://developer.microsoft.com/json-schemas/fabric/pbip/pbipProperties/1.0.0/schema.json",
        "version": "1.0", "artifacts": [{"report": {"path": f"{NAME}.Report"}}], "settings": {"enableAutoRecovery": True}})
    write_json(model_dir / "definition.pbism", {
        "$schema": f"{SCHEMA}/semanticModel/definitionProperties/1.0.0/schema.json", "version": "1.0", "settings": {}})
    write_json(model_dir / "model.bim", semantic_model())

    write_json(report_dir / "definition.pbir", {
        "$schema": f"{SCHEMA}/report/definitionProperties/2.0.0/schema.json", "version": "4.0",
        "datasetReference": {"byPath": {"path": f"../{NAME}.SemanticModel"}}})
    definition = report_dir / "definition"
    write_json(definition / "version.json", {
        "$schema": f"{SCHEMA}/report/definition/versionMetadata/1.0.0/schema.json", "version": "2.0.0"})
    version_at_import = {"visual": "2.10.0", "report": "3.2.0", "page": "2.0.0"}
    write_json(definition / "report.json", {
        "$schema": f"{SCHEMA}/report/definition/report/3.2.0/schema.json",
        "themeCollection": {
            "baseTheme": {"name": THEME, "type": "SharedResources", "reportVersionAtImport": version_at_import},
            "customTheme": {"name": f"{THEME_NAME}.json", "type": "RegisteredResources", "reportVersionAtImport": version_at_import},
        },
        "resourcePackages": [
            {"name": "SharedResources", "type": "SharedResources",
             "items": [{"name": THEME, "path": f"BaseThemes/{THEME}.json", "type": "BaseTheme"}]},
            {"name": "RegisteredResources", "type": "RegisteredResources",
             "items": [{"name": f"{THEME_NAME}.json", "path": f"{THEME_NAME}.json", "type": "CustomTheme"}]},
        ],
    })
    themes_dir = report_dir / "StaticResources" / "SharedResources" / "BaseThemes"
    themes_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(args.theme_file, themes_dir / f"{THEME}.json")
    write_json(report_dir / "StaticResources" / "RegisteredResources" / f"{THEME_NAME}.json", theme())

    pages = build_pages()
    write_json(definition / "pages" / "pages.json", {
        "$schema": f"{SCHEMA}/report/definition/pagesMetadata/1.0.0/schema.json",
        "pageOrder": [p.name for p in pages], "activePageName": pages[0].name})
    for page in pages:
        write_json(definition / "pages" / page.name / "page.json", {
            "$schema": f"{SCHEMA}/report/definition/page/2.0.0/schema.json",
            "name": page.name, "displayName": page.display, "displayOption": "FitToPage",
            "height": PAGE_H, "width": PAGE_W})
        for visual in page.visuals:
            write_json(definition / "pages" / page.name / "visuals" / visual["name"] / "visual.json", visual)
    print(f"Wrote {OUT.relative_to(ROOT)}: {sum(len(p.visuals) for p in pages)} visuals on {len(pages)} pages")


if __name__ == "__main__":
    main()
