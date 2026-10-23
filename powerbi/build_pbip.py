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

STATUS_COLORS = {
    "Current": "#2E7D32", "1 month behind": "#F9A825", "2 months behind": "#EF6C00",
    "3-5 months behind": "#D84315", "6+ months behind": "#B71C1C",
    "Unsupported OS": "#4A148C", "Unverified version": "#9E9E9E",
}
RISK_COLORS = {"Low": "#2E7D32", "Medium": "#F9A825", "High": "#EF6C00", "Critical": "#B71C1C", "Unknown": "#9E9E9E"}

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
]
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
    ("Devices Behind", f"CALCULATE ( [Devices], {DEV}[PatchesBehind] >= 1 )", "#,0"),
    ("Devices Critical Risk", f'CALCULATE ( [Devices], {DEV}[RiskLevel] = "Critical" )', "#,0"),
    ("Devices Unsupported OS", f'CALCULATE ( [Devices], {DEV}[PatchStatus] = "Unsupported OS" )', "#,0"),
    ("Devices Unverified", f'CALCULATE ( [Devices], {DEV}[PatchStatus] = "Unverified version" )', "#,0"),
    ("Avg Patches Behind", f"AVERAGEX ( FILTER ( {DEV}, NOT ISBLANK ( {DEV}[PatchesBehind] ) ), {DEV}[PatchesBehind] )", "0.0"),
    ("Devices Missing Exploited CVEs", f"CALCULATE ( [Devices], {DEV}[ExploitedCVEsMissed] > 0 )", "#,0"),
    ("Latest Patch Month", f'FORMAT ( MAX ( {CAT}[PatchMonthStart] ), "MMM-yyyy" )', None),
    ("Report Subtitle",
     f'"Data: " & SELECTEDVALUE ( {DEV}[DataSource], "Defender" ) & "  |  Devices seen up to " '
     f'& FORMAT ( MAX ( {DEV}[LastSeen] ), "dd-MMM-yyyy HH:mm" ) & "  |  Latest Microsoft release: " & [Latest Patch Month]', None),
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
    names = [c for c, _, _ in DEVICE_COLUMNS if c != "DataSource"]
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
    Typed = Table.TransformColumnTypes(WithSource, {{{types}}})
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

def table(name, columns, query, measures=(), sort_by=None):
    sort_by = sort_by or {}
    return {
        "name": name,
        "columns": [{
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
                      {"PatchStatus": "PatchStatusOrder", "PatchMonth": "PatchMonthStart"}),
                table(CAT, CATALOG_COLUMNS, catalog_query(), sort_by={"PatchMonth": "PatchMonthStart"}),
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

def col(entity, prop):
    return {"Column": {"Expression": {"SourceRef": {"Entity": entity}}, "Property": prop}}


def measure(prop, entity=DEV):
    return {"Measure": {"Expression": {"SourceRef": {"Entity": entity}}, "Property": prop}}


DISPLAY_NAMES = {
    "DeviceName": "Device", "MachineGroup": "Device group", "OSName": "OS version", "DeviceOSBuild": "Installed build",
    "PatchMonth": "Patch month", "InstalledSecurityKB": "Installed security KB", "PatchesBehind": "Releases behind",
    "CVEsMissed": "CVEs missed", "CriticalCVEsMissed": "Critical CVEs missed", "ExploitedCVEsMissed": "Exploited CVEs missed",
    "LatestBuild": "Latest build", "RiskLevel": "Risk", "LastSeen": "Last seen", "PatchStatus": "Patch status",
    "OSLatestPatchMonth": "Latest patch month", "OSLatestFullBuild": "Latest build", "KB": "KB", "FullBuild": "Build",
    "CVECount": "CVEs fixed", "CriticalCVECount": "Critical", "ExploitedCVECount": "Exploited",
    "ReleaseDate": "Release date", "OSStillServiced": "Still serviced",
}


def projection(field):
    kind = "Measure" if "Measure" in field else "Column"
    entity = field[kind]["Expression"]["SourceRef"]["Entity"]
    prop = field[kind]["Property"]
    result = {"field": field, "queryRef": f"{entity}.{prop}", "nativeQueryRef": prop}
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


class Page:
    def __init__(self, name, display):
        self.name, self.display, self.visuals = name, display, []

    def add(self, visual_type, x, y, w, h, roles=None, title=None, objects=None, sort=None, filters=None):
        visual = {"visualType": visual_type, "drillFilterOtherVisuals": True}
        if roles:
            visual["query"] = {"queryState": {role: {"projections": [projection(f) for f in fields]}
                                              for role, fields in roles.items()}}
            if sort:
                field, direction = sort
                visual["query"]["sortDefinition"] = {"sort": [{"field": field, "direction": direction}],
                                                     "isDefaultSort": True}
        if visual_type == "slicer":  # the visual title already names the field
            objects = {**(objects or {}), "header": [{"properties": {"show": lit(False)}}]}
        if objects:
            visual["objects"] = objects
        container = {
            "$schema": f"{SCHEMA}/report/definition/visualContainer/2.10.0/schema.json",
            "name": f"{self.name}_{len(self.visuals):02d}",
            "position": {"x": x, "y": y, "z": len(self.visuals) * 1000, "width": w, "height": h,
                         "tabOrder": len(self.visuals) * 1000},
            "visual": visual,
        }
        if title:
            visual["visualContainerObjects"] = {"title": [{"properties": {"show": lit(True), "text": lit(title)}}]}
        if filters:
            container["filterConfig"] = {"filters": filters}
        self.visuals.append(container)


def in_filter(name, entity, prop, values):
    return {
        "name": name, "field": col(entity, prop), "type": "Categorical",
        "filter": {"Version": 2, "From": [{"Name": "t", "Entity": entity, "Type": 0}],
                   "Where": [{"Condition": {"In": {
                       "Expressions": [{"Column": {"Expression": {"SourceRef": {"Source": "t"}}, "Property": prop}}],
                       "Values": [[{"Literal": lit(v)["expr"]["Literal"]}] for v in values]}}}]},
    }


def category_colors(entity, prop, colors):
    return [{"properties": {"fill": color(c)},
             "selector": {"data": [{"scopeId": {"Comparison": {
                 "ComparisonKind": 0, "Left": col(entity, prop), "Right": {"Literal": lit(v)["expr"]["Literal"]}}}}]}}
            for v, c in colors.items()]


def textbox(page, x, y, w, h, text, size, bold=False, field=None):
    paragraphs = [{"textRuns": [{"value": text, "textStyle": {"fontSize": f"{size}pt", **({"fontWeight": "bold"} if bold else {})}}]}]
    page.add("textbox", x, y, w, h, objects={"general": [{"properties": {"paragraphs": paragraphs}}]})


def build_pages() -> list[Page]:
    overview = Page("overview", "Patch risk overview")
    textbox(overview, 16, 8, 900, 40, "Windows patch risk – Microsoft Defender for Endpoint", 18, bold=True)
    overview.add("card", 920, 4, 344, 52, {"Values": [measure("Report Subtitle")]},
                 objects={"labels": [{"properties": {"fontSize": lit(9)}}], "categoryLabels": [{"properties": {"show": lit(False)}}]})
    for i, (prop, label) in enumerate([("RiskLevel", "Risk level"), ("Platform", "Platform"),
                                       ("MachineGroup", "Device group"), ("OSName", "OS version")]):
        overview.add("slicer", 16, 64 + i * 162, 200, 154, {"Values": [col(DEV, prop)]}, title=label)
    cards = [("Devices", "Devices"), ("% Current", "% fully patched"), ("Devices Critical Risk", "Critical risk"),
             ("Avg Patches Behind", "Avg. releases behind"), ("Devices Missing Exploited CVEs", "Missing exploited CVE fixes"),
             ("Devices Unsupported OS", "Unsupported OS"), ("Devices Unverified", "Unverified version")]
    width = (1264 - 232 - 6 * 8) / 7
    for i, (prop, label) in enumerate(cards):
        overview.add("card", 232 + i * (width + 8), 64, width, 96, {"Values": [measure(prop)]}, title=label,
                     objects={"categoryLabels": [{"properties": {"show": lit(False)}}]})
    overview.add("donutChart", 232, 172, 380, 270, {"Category": [col(DEV, "PatchStatus")], "Y": [measure("Devices")]},
                 title="Devices by patch status",
                 objects={"dataPoint": category_colors(DEV, "PatchStatus", STATUS_COLORS)})
    overview.add("barChart", 620, 172, 644, 270,
                 {"Category": [col(DEV, "OSName")], "Y": [measure("Devices")], "Series": [col(DEV, "PatchStatus")]},
                 title="Patch status by OS version",
                 objects={"dataPoint": category_colors(DEV, "PatchStatus", STATUS_COLORS)})
    overview.add("clusteredColumnChart", 232, 452, 470, 262,
                 {"Category": [col(DEV, "PatchMonth")], "Y": [measure("Devices")]},
                 title="Devices by installed patch month", sort=(col(DEV, "PatchMonth"), "Ascending"))
    overview.add("tableEx", 710, 452, 554, 262,
                 {"Values": [col(DEV, c) for c in ("DeviceName", "OSName", "PatchMonth", "PatchesBehind", "RiskLevel")]},
                 title="Devices furthest behind", sort=(col(DEV, "PatchesBehind"), "Descending"))

    attention = Page("attention", "Needs attention")
    textbox(attention, 16, 8, 1200, 40, "Devices at Critical or High risk – hand-off list for the patching team", 16, bold=True)
    attention.add("slicer", 16, 60, 220, 300, {"Values": [col(DEV, "MachineGroup")]}, title="Device group")
    attention.add("slicer", 16, 368, 220, 340, {"Values": [col(DEV, "OSName")]}, title="OS version")
    attention.add("tableEx", 248, 60, 1016, 648,
                  {"Values": [col(DEV, c) for c in ("DeviceName", "MachineGroup", "OSName", "DeviceOSBuild", "PatchMonth",
                                                    "InstalledSecurityKB", "PatchesBehind", "CVEsMissed", "CriticalCVEsMissed",
                                                    "ExploitedCVEsMissed", "LatestBuild", "RiskLevel", "LastSeen")]},
                  title="Critical and High risk devices", sort=(col(DEV, "PatchesBehind"), "Descending"),
                  filters=[in_filter("riskFilter", DEV, "RiskLevel", ["Critical", "High"])])

    catalog = Page("catalog", "Windows release catalog")
    textbox(catalog, 16, 8, 1200, 40, "Windows security releases (Microsoft MSRC) – refreshed automatically", 16, bold=True)
    catalog.add("tableEx", 16, 60, 1248, 300,
                {"Values": [col(CAT, c) for c in ("OSName", "Platform", "OSLatestPatchMonth", "OSLatestFullBuild", "KB",
                                                  "CVECount", "OSStillServiced")]},
                title="Latest release per Windows version", sort=(col(CAT, "OSName"), "Ascending"),
                filters=[in_filter("latestOnly", CAT, "IsLatestForOS", [True])])
    catalog.add("slicer", 16, 372, 260, 336, {"Values": [col(CAT, "OSName")]}, title="OS version")
    catalog.add("tableEx", 288, 372, 976, 336,
                {"Values": [col(CAT, c) for c in ("OSName", "PatchMonth", "KB", "FullBuild", "CVECount",
                                                  "CriticalCVECount", "ExploitedCVECount", "ReleaseDate")]},
                title="Release history", sort=(col(CAT, "ReleaseDate"), "Descending"))
    return [overview, attention, catalog]


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
        "$schema": "https://developer.microsoft.com/json-schemas/fabric/pbip/pbipProperties/1.0.0/schema.json", "version": "1.0",
        "artifacts": [{"report": {"path": f"{NAME}.Report"}}], "settings": {"enableAutoRecovery": True}})
    write_json(model_dir / "definition.pbism", {
        "$schema": f"{SCHEMA}/semanticModel/definitionProperties/1.0.0/schema.json", "version": "1.0", "settings": {}})
    write_json(model_dir / "model.bim", semantic_model())

    write_json(report_dir / "definition.pbir", {
        "$schema": f"{SCHEMA}/report/definitionProperties/2.0.0/schema.json", "version": "4.0",
        "datasetReference": {"byPath": {"path": f"../{NAME}.SemanticModel"}}})
    definition = report_dir / "definition"
    write_json(definition / "version.json", {
        "$schema": f"{SCHEMA}/report/definition/versionMetadata/1.0.0/schema.json", "version": "2.0.0"})
    write_json(definition / "report.json", {
        "$schema": f"{SCHEMA}/report/definition/report/3.2.0/schema.json",
        "themeCollection": {"baseTheme": {"name": THEME, "type": "SharedResources",
                                          "reportVersionAtImport": {"visual": "2.10.0", "report": "3.2.0", "page": "2.0.0"}}},
    })
    themes_dir = report_dir / "StaticResources" / "SharedResources" / "BaseThemes"
    themes_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(args.theme_file, themes_dir / f"{THEME}.json")
    pages = build_pages()
    write_json(definition / "pages" / "pages.json", {
        "$schema": f"{SCHEMA}/report/definition/pagesMetadata/1.0.0/schema.json",
        "pageOrder": [p.name for p in pages], "activePageName": pages[0].name})
    for page in pages:
        write_json(definition / "pages" / page.name / "page.json", {
            "$schema": f"{SCHEMA}/report/definition/page/2.0.0/schema.json",
            "name": page.name, "displayName": page.display, "displayOption": "FitToPage", "height": 720, "width": 1280})
        for visual in page.visuals:
            write_json(definition / "pages" / page.name / "visuals" / visual["name"] / "visual.json", visual)
    print(f"Wrote {OUT.relative_to(ROOT)}: {sum(len(p.visuals) for p in pages)} visuals on {len(pages)} pages")


if __name__ == "__main__":
    main()
