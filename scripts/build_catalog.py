"""Build a catalog of Windows monthly security releases from the Microsoft MSRC CVRF API.

For every Windows client and server version Microsoft has published security updates for
(Windows Vista/7/8.1/10/11, Windows Server 2008 -> 2025 and anything newer), the catalog
holds one row per Patch Tuesday release: KB, fixed OS build, patch month (MMM-YYYY) and the
number of CVEs fixed. Microsoft Defender for Endpoint KQL joins on Platform + BuildNumber
and compares the device's build revision to work out its patch month and how far behind it is.

Pipeline:
  1. Read the MSRC update index (one CVRF document per month, April 2016 onwards).
  2. Download only the months that are new or that Microsoft has revised since the last run
     (a compact extract of each month is cached in data/cache/msrc).
  3. Date every build/KB to the month whose document it fixes the most CVEs in (Microsoft
     revises old documents to list newer KBs, so "appears in" is not "released in"), keep the
     main release per OS version per month, and derive ranks and "CVEs released since" totals.
  4. Validate the result, archive the previous CSV if the release list changed, write the new one.

Usage:
  python scripts/build_catalog.py                 # incremental (normal scheduled run)
  python scripts/build_catalog.py --full-refresh  # ignore the cache and rebuild everything
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import io
import json
import logging
import os
import re
import shutil
import ssl
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

API_BASE = "https://api.msrc.microsoft.com/cvrf/v3.0"
FIRST_DOCUMENT_MONTH = dt.date(2016, 4, 1)  # first month MSRC published as CVRF
EXTRACT_VERSION = 2  # bump when extract_releases() changes so cached months are rebuilt

CATALOG_FILE = "Windows_Security_Releases.csv"
METADATA_FILE = "catalog_metadata.json"

CSV_COLUMNS = [
    "OSFamily", "OSName", "Platform", "BuildNumber", "Revision", "FullBuild",
    "KB", "UpdateType", "PatchMonth", "PatchMonthStart", "ReleaseDate",
    "ReleaseRank", "IsLatestForOS",
    "CVECount", "CriticalCVECount", "ExploitedCVECount",
    "CVEsReleasedSince", "CriticalCVEsReleasedSince", "ExploitedCVEsReleasedSince",
    "OSLatestPatchMonth", "OSLatestFullBuild", "OSStillServiced", "MsrcDocumentId",
]

# Remediation sub-types that represent an OS security release. Lower value wins when one
# build ships under several KBs (Windows 7/8.1 Monthly Rollup vs Security Only).
UPDATE_SUBTYPE_PRIORITY = {"Security Update": 0, "Monthly Rollup": 1, "Security Only": 2}

MONTH_ABBR = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

# MSRC only started publishing FixedBuild in 2021. These build numbers cover OS versions whose
# releases predate that; anything newer is learned from FixedBuild automatically.
KNOWN_BUILD_NUMBERS = {
    "Windows Vista": 6002, "Windows Server 2008": 6003, "Windows 7": 7601,
    "Windows Server 2008 R2": 7601, "Windows 8": 9200, "Windows Server 2012": 9200,
    "Windows 8.1": 9600, "Windows Server 2012 R2": 9600,
    "Windows 10 Version 1507": 10240, "Windows 10 Version 1511": 10586, "Windows 10 Version 1607": 14393,
    "Windows 10 Version 1703": 15063, "Windows 10 Version 1709": 16299,
    "Windows 10 Version 1803": 17134, "Windows 10 Version 1809": 17763,
    "Windows 10 Version 1903": 18362, "Windows 10 Version 1909": 18363,
    "Windows 10 Version 2004": 19041, "Windows 10 Version 20H2": 19042,
    "Windows 10 Version 21H1": 19043, "Windows 10 Version 21H2": 19044,
    "Windows 10 Version 22H2": 19045, "Windows 11 Version 21H2": 22000,
    "Windows 11 Version 22H2": 22621, "Windows 11 Version 23H2": 22631,
    "Windows 11 Version 24H2": 26100, "Windows Server 2016": 14393,
    "Windows Server 2019": 17763, "Windows Server 2022": 20348, "Windows Server 2025": 26100,
    "Windows Server, Version 1709": 16299, "Windows Server, Version 1803": 17134,
    "Windows Server, Version 1903": 18362, "Windows Server, Version 1909": 18363,
    "Windows Server, Version 2004": 19041, "Windows Server, Version 20H2": 19042,
}

# MSRC product names that are ambiguous on their own.
OS_NAME_ALIASES = {"Windows 10": "Windows 10 Version 1507", "Windows 11": "Windows 11 Version 21H2"}

BUILD_RE = re.compile(r"\d+\.\d+\.(\d+)\.(\d+)")
ARCH_RE = re.compile(r"\s+for\s+(?:x64|x86|32-bit|64-bit|ARM64|ARM|Itanium)[\w\s-]*?systems", re.I)
CLIENT_RE = re.compile(r"Windows (?:Vista|\d{1,2}(?:\.1)?)(?: Version \w+)?")
SERVER_RE = re.compile(r"Windows Server (?:20\d\d(?: R2)?)")
SERVER_SAC_RE = re.compile(r"Windows Server,? Version (\w+)")

log = logging.getLogger("catalog")


class ValidationError(Exception):
    pass


# --------------------------------------------------------------------------- MSRC access

class MsrcClient:
    """Read-only HTTPS client for the MSRC API (standard library only, TLS verified, retries)."""

    ALLOWED_PREFIX = API_BASE + "/"
    MAX_BYTES = 200 * 1024 * 1024  # largest monthly document is ~30 MB

    def __init__(self) -> None:
        self.context = ssl.create_default_context()

    def get_json(self, url: str) -> dict:
        if not url.startswith(self.ALLOWED_PREFIX):  # never follow URLs to other hosts
            raise ValueError(f"Refusing to fetch non-MSRC URL: {url}")
        request = urllib.request.Request(url, headers={
            "Accept": "application/json", "User-Agent": "mde-windows-patch-catalog"})
        for attempt in range(1, 6):
            try:
                with urllib.request.urlopen(request, timeout=180, context=self.context) as response:
                    body = response.read(self.MAX_BYTES + 1)
                if len(body) > self.MAX_BYTES:
                    raise ValueError(f"Response from {url} exceeds {self.MAX_BYTES} bytes")
                return json.loads(body.decode("utf-8"))
            except urllib.error.HTTPError as error:
                if error.code not in (429, 500, 502, 503, 504) or attempt == 5:
                    raise
            except (urllib.error.URLError, TimeoutError, ConnectionError):
                if attempt == 5:
                    raise
            log.warning("Retrying %s (attempt %d)", url, attempt + 1)
            time.sleep(2 ** attempt)
        raise RuntimeError("unreachable")


def parse_document_month(doc_id: str) -> dt.date | None:
    """'2026-Oct' -> 2026-10-01. Tolerates the odd IDs MSRC has used ('2018-FEB', '2017-May-B')."""
    match = re.match(r"(\d{4})-([A-Za-z]{3})", doc_id)
    if not match or match.group(2).title() not in MONTH_ABBR:
        return None
    return dt.date(int(match.group(1)), MONTH_ABBR.index(match.group(2).title()) + 1, 1)


# --------------------------------------------------------------------------- extraction

def normalize_product(name: str) -> tuple[str, str] | None:
    """Map an MSRC product name to (OSName, Platform), or None if it is not a Windows OS.

    'Windows 11 Version 24H2 for x64-based Systems'      -> ('Windows 11 Version 24H2', 'Client')
    'Windows Server 2019 (Server Core installation)'      -> ('Windows Server 2019', 'Server')
    'Windows 7 for x64-based Systems Service Pack 1'      -> ('Windows 7', 'Client')
    """
    n = re.sub(r"\s*\(Server Core installation\)", "", name)
    n = ARCH_RE.sub("", n)
    n = re.sub(r"\s+Service Pack \d+", "", n)
    n = re.sub(r"\s+x64 Edition", "", n)
    n = re.sub(r"\bversion\b", "Version", n)
    n = re.sub(r"\s+", " ", n).strip()
    if CLIENT_RE.fullmatch(n):
        return OS_NAME_ALIASES.get(n, n), "Client"
    if SERVER_RE.fullmatch(n):
        return n, "Server"
    sac = SERVER_SAC_RE.fullmatch(n)
    if sac:
        return f"Windows Server, Version {sac.group(1)}", "Server"
    return None


def os_family(os_name: str, platform: str) -> str:
    if platform == "Server":
        return "Windows Server"
    return " ".join(os_name.split(" ")[:2])  # 'Windows 11 Version 24H2' -> 'Windows 11'


@dataclass
class Candidate:
    fixed_build: str
    kbs: dict[str, str] = field(default_factory=dict)  # KB -> sub-type
    cves: set[str] = field(default_factory=set)
    critical: set[str] = field(default_factory=set)
    exploited: set[str] = field(default_factory=set)

    def preferred_kb(self) -> tuple[str, str]:
        return min(self.kbs.items(), key=lambda kv: (UPDATE_SUBTYPE_PRIORITY[kv[1]], kv[0]))


def extract_releases(doc: dict) -> list[dict]:
    """Return every Windows OS security release (build or KB) one monthly CVRF document lists,
    with the number of that document's CVEs it fixes per OS version."""
    products = {}
    for product in doc.get("ProductTree", {}).get("FullProductName", []):
        normalized = normalize_product(product.get("Value", ""))
        if normalized:
            products[product["ProductID"]] = normalized

    candidates: dict[tuple[str, str], dict[str, Candidate]] = defaultdict(dict)
    for vuln in doc.get("Vulnerability") or []:
        cve = vuln.get("CVE")
        if not cve:
            continue
        critical_pids, exploited_pids, exploited_everywhere = set(), set(), False
        for threat in vuln.get("Threats") or []:
            value = ((threat.get("Description") or {}).get("Value") or "").replace(" ", "").lower()
            pids = threat.get("ProductID") or []
            if threat.get("Type") == 3 and value == "critical":
                critical_pids.update(pids)
            elif threat.get("Type") == 1 and "exploited:yes" in value:
                exploited_pids.update(pids)
                exploited_everywhere |= not pids

        for rem in vuln.get("Remediations") or []:
            subtype = (rem.get("SubType") or "").strip()
            kb_number = ((rem.get("Description") or {}).get("Value") or "").strip()
            if rem.get("Type") != 2 or subtype not in UPDATE_SUBTYPE_PRIORITY or not kb_number.isdigit():
                continue
            fixed_build = (rem.get("FixedBuild") or "").strip()
            if not BUILD_RE.fullmatch(fixed_build):
                fixed_build = ""
            for pid in rem.get("ProductID") or []:
                os_key = products.get(pid)
                if not os_key:
                    continue
                key = fixed_build or f"KB{kb_number}"
                candidate = candidates[os_key].setdefault(key, Candidate(fixed_build))
                candidate.kbs.setdefault(f"KB{kb_number}", subtype)
                candidate.cves.add(cve)
                if pid in critical_pids:
                    candidate.critical.add(cve)
                if exploited_everywhere or pid in exploited_pids:
                    candidate.exploited.add(cve)

    releases = []
    for (os_name, platform), options in candidates.items():
        for candidate in options.values():
            kb, subtype = candidate.preferred_kb()
            releases.append({
                "OSName": os_name, "Platform": platform, "KB": kb, "UpdateType": subtype,
                "FixedBuild": candidate.fixed_build, "CVECount": len(candidate.cves),
                "CriticalCVECount": len(candidate.critical), "ExploitedCVECount": len(candidate.exploited),
            })
    return sorted(releases, key=lambda r: (r["Platform"], r["OSName"], -r["CVECount"]))


def increasing_build_sequence(rows: list[dict]) -> set[int]:
    """ids of the rows (sorted by month) whose build revisions rise month on month and that
    together fix the most CVEs. Rows without a published build carry no order and are kept."""
    built = [r for r in rows if revision_of(r["FixedBuild"]) >= 0]
    best, previous = [], []
    for i, row in enumerate(built):
        score, parent = 0, -1
        for j in range(i):
            if revision_of(built[j]["FixedBuild"]) < revision_of(row["FixedBuild"]) and best[j] > score:
                score, parent = best[j], j
        best.append(score + row["CVECount"] + 1)
        previous.append(parent)
    kept = {id(r) for r in rows if revision_of(r["FixedBuild"]) < 0}
    i = max(range(len(built)), key=best.__getitem__) if built else -1
    while i >= 0:
        kept.add(id(built[i]))
        i = previous[i]
    return kept


def release_identity(release: dict) -> str:
    return release["FixedBuild"] or release["KB"]


def revision_of(fixed_build: str) -> int:
    match = BUILD_RE.fullmatch(fixed_build or "")
    return int(match.group(2)) if match else -1


# --------------------------------------------------------------------------- cache

def load_month_extracts(client: MsrcClient, cache_dir: Path, full_refresh: bool) -> list[dict]:
    """Return one extract per monthly document, downloading only new or revised months."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    index = client.get_json(f"{API_BASE}/updates")["value"]
    extracts = []
    downloaded = 0
    for entry in sorted(index, key=lambda e: e["InitialReleaseDate"]):
        month = parse_document_month(entry["ID"])
        if not month or month < FIRST_DOCUMENT_MONTH or "Security Update" not in (entry.get("DocumentTitle") or ""):
            continue
        if not re.fullmatch(r"[0-9A-Za-z-]{6,20}", entry["ID"]):  # used as a file name
            raise ValueError(f"Unexpected MSRC document ID: {entry['ID']!r}")
        cache_file = cache_dir / f"{entry['ID']}.json"
        cached = json.loads(cache_file.read_text(encoding="utf-8")) if cache_file.exists() else None
        if (not full_refresh and cached and cached.get("ExtractVersion") == EXTRACT_VERSION
                and cached.get("CurrentReleaseDate") == entry["CurrentReleaseDate"]):
            extracts.append(cached)
            continue

        log.info("Downloading %s (revised %s)", entry["ID"], entry["CurrentReleaseDate"])
        doc = client.get_json(entry["CvrfUrl"])
        extract = {
            "ExtractVersion": EXTRACT_VERSION,
            "ID": entry["ID"],
            "PatchMonthStart": month.isoformat(),
            "ReleaseDate": entry["InitialReleaseDate"][:10],
            "CurrentReleaseDate": entry["CurrentReleaseDate"],
            "Releases": extract_releases(doc),
        }
        cache_file.write_text(json.dumps(extract, indent=1), encoding="utf-8")
        extracts.append(extract)
        downloaded += 1
    log.info("%d monthly documents (%d downloaded, %d from cache)", len(extracts), downloaded, len(extracts) - downloaded)
    return extracts


# --------------------------------------------------------------------------- catalog

def build_catalog(extracts: list[dict]) -> list[dict]:
    extracts = sorted(extracts, key=lambda e: (e["PatchMonthStart"], e["ID"]))

    # Home month of a build/KB = the month whose document it fixes the most CVEs in.
    cves_per_month: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    build_votes: dict[str, dict[int, int]] = defaultdict(lambda: defaultdict(int))
    for extract in extracts:
        for release in extract["Releases"]:
            cves_per_month[release_identity(release)][extract["PatchMonthStart"]] += release["CVECount"]
            match = BUILD_RE.fullmatch(release["FixedBuild"])
            if match:
                build_votes[release["OSName"]][int(match.group(1))] += 1
    home_month = {identity: max(months.items(), key=lambda kv: kv[1])[0]  # ties: earliest
                  for identity, months in cves_per_month.items()}
    build_numbers = dict(KNOWN_BUILD_NUMBERS)
    build_numbers.update({os_name: max(votes, key=votes.get) for os_name, votes in build_votes.items()})

    # Main release per OS version per month: the one fixing the most CVEs among those homed there.
    chosen: dict[tuple[str, str], dict] = {}
    for extract in extracts:
        month = extract["PatchMonthStart"]
        for release in extract["Releases"]:
            if home_month[release_identity(release)] != month:
                continue
            key = (release["OSName"], month)
            if key not in chosen or release["CVECount"] > chosen[key]["CVECount"]:
                chosen[key] = {**release, "PatchMonthStart": month, "ReleaseDate": extract["ReleaseDate"],
                               "MsrcDocumentId": extract["ID"]}

    by_os: dict[str, list[dict]] = defaultdict(list)
    for row in sorted(chosen.values(), key=lambda r: r["PatchMonthStart"]):
        match = BUILD_RE.fullmatch(row["FixedBuild"])
        if match and int(match.group(1)) != build_numbers.get(row["OSName"]):
            # Shared KB listed with a sibling's build (22H2 vs 23H2, 21H2 vs 22H2): same revision.
            build = build_numbers[row["OSName"]]
            prefix = "10.0" if build >= 10240 else ".".join(row["FixedBuild"].split(".")[:2])
            row["FixedBuild"] = f"{prefix}.{build}.{match.group(2)}"
        by_os[row["OSName"]].append(row)

    catalog = []
    for os_name, rows in by_os.items():
        # Noise: one-off KBs that only appear in revised old documents fix a CVE or two.
        typical = sorted(r["CVECount"] for r in rows)[len(rows) // 2]
        rows = [r for r in rows if r["CVECount"] >= 0.1 * typical]
        kept = increasing_build_sequence(rows)
        for row in rows:
            if id(row) not in kept:
                log.warning("Skipping %s %s %s (%d CVEs): out of build order", os_name,
                            row["PatchMonthStart"][:7], row["FixedBuild"], row["CVECount"])
        catalog.extend(r for r in rows if id(r) in kept)

    catalog_latest_month = max(r["PatchMonthStart"] for r in catalog)
    final = []
    for os_name in sorted(by_os):
        rows = sorted((r for r in catalog if r["OSName"] == os_name), key=lambda r: r["PatchMonthStart"], reverse=True)
        if not rows:
            continue
        latest = rows[0]
        since = {"CVECount": 0, "CriticalCVECount": 0, "ExploitedCVECount": 0}
        for rank, row in enumerate(rows, start=1):
            month = dt.date.fromisoformat(row["PatchMonthStart"])
            match = BUILD_RE.fullmatch(row["FixedBuild"])
            final.append({
                "OSFamily": os_family(os_name, row["Platform"]),
                "OSName": os_name,
                "Platform": row["Platform"],
                "BuildNumber": build_numbers.get(os_name, ""),
                "Revision": int(match.group(2)) if match else "",
                "FullBuild": row["FixedBuild"],
                "KB": row["KB"],
                "UpdateType": row["UpdateType"],
                "PatchMonth": f"{MONTH_ABBR[month.month - 1]}-{month.year}",
                "PatchMonthStart": row["PatchMonthStart"],
                "ReleaseDate": row["ReleaseDate"],
                "ReleaseRank": rank,
                "IsLatestForOS": rank == 1,
                "CVECount": row["CVECount"],
                "CriticalCVECount": row["CriticalCVECount"],
                "ExploitedCVECount": row["ExploitedCVECount"],
                "CVEsReleasedSince": since["CVECount"],
                "CriticalCVEsReleasedSince": since["CriticalCVECount"],
                "ExploitedCVEsReleasedSince": since["ExploitedCVECount"],
                "OSLatestPatchMonth": format_month(latest["PatchMonthStart"]),
                "OSLatestFullBuild": latest["FixedBuild"],
                "OSStillServiced": latest["PatchMonthStart"] == catalog_latest_month,
                "MsrcDocumentId": row["MsrcDocumentId"],
            })
            for key in since:
                since[key] += row[key]

    final.sort(key=lambda r: (r["Platform"], r["OSFamily"], r["OSName"], r["ReleaseRank"]))
    return final


def format_month(iso_date: str) -> str:
    month = dt.date.fromisoformat(iso_date)
    return f"{MONTH_ABBR[month.month - 1]}-{month.year}"


def to_csv(rows: list[dict]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({k: str(v).lower() if isinstance(v, bool) else v for k, v in row.items()})
    return buffer.getvalue()


def read_csv(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


# --------------------------------------------------------------------------- validation

def validate(rows: list[dict], previous: list[dict]) -> None:
    """Refuse to publish a catalog that would break or mislead the dashboard."""
    if len(rows) < 100:
        raise ValidationError(f"Only {len(rows)} rows produced; expected several hundred")
    if previous:
        if set(previous[0]) != set(CSV_COLUMNS):
            log.warning("Column set differs from the previous file (schema change)")
        if len(rows) < 0.95 * len(previous):
            raise ValidationError(f"Row count dropped from {len(previous)} to {len(rows)}")
        previous_latest = max(r["PatchMonthStart"] for r in previous)
        if max(r["PatchMonthStart"] for r in rows) < previous_latest:
            raise ValidationError(f"Latest patch month went backwards (previous {previous_latest})")

    serviced = {r["OSName"] for r in rows if r["OSStillServiced"]}
    for required in ("Windows 11", "Windows Server"):
        if not any(name.startswith(required) for name in serviced):
            raise ValidationError(f"No currently serviced '{required}' version found")

    seen = set()
    for row in rows:
        key = (row["OSName"], row["PatchMonthStart"])
        if key in seen:
            raise ValidationError(f"Duplicate release for {key}")
        seen.add(key)
        if row["OSStillServiced"] and row["IsLatestForOS"] and not row["FullBuild"]:
            raise ValidationError(f"{row['OSName']} {row['PatchMonth']} has no fixed build")


# --------------------------------------------------------------------------- publish

def release_identities(rows: list[dict]) -> set[tuple]:
    return {(r["OSName"], r["PatchMonth"], str(r["FullBuild"]), r["KB"]) for r in rows}


def archive_name(previous: list[dict], archive_dir: Path) -> Path:
    """Windows_Security_Releases_MMYYYY.csv for the latest patch month the old file held."""
    latest = max(r["PatchMonthStart"] for r in previous)
    stem = Path(CATALOG_FILE).stem
    target = archive_dir / f"{stem}_{latest[5:7]}{latest[:4]}.csv"
    if target.exists():  # a second change in the same month (out-of-band release, MSRC correction)
        target = archive_dir / f"{stem}_{latest[5:7]}{latest[:4]}_{dt.date.today():%Y%m%d}.csv"
    return target


def write_github_outputs(outputs: dict) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with open(path, "a", encoding="utf-8") as handle:
            for key, value in outputs.items():
                handle.write(f"{key}={value}\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data-dir", default="data", type=Path)
    parser.add_argument("--full-refresh", action="store_true", help="ignore cached monthly extracts")
    parser.add_argument("--summary-out", type=Path, help="write a Markdown run summary here")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    data_dir: Path = args.data_dir
    catalog_path = data_dir / CATALOG_FILE
    previous = read_csv(catalog_path)

    extracts = load_month_extracts(MsrcClient(), data_dir / "cache" / "msrc", args.full_refresh)
    rows = build_catalog(extracts)
    validate(rows, previous)

    new_text = to_csv(rows)
    old_text = catalog_path.read_text(encoding="utf-8") if catalog_path.exists() else ""
    changed = new_text != old_text
    new_releases = sorted(release_identities(read_csv_text(new_text)) - release_identities(previous),
                          key=lambda r: (dt.datetime.strptime(r[1], "%b-%Y"), r[0]), reverse=True)
    material = bool(new_releases) or (bool(previous) and set(previous[0]) != set(CSV_COLUMNS))

    archived = ""
    if material and previous:
        target = archive_name(previous, data_dir / "archive")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(catalog_path, target)
        archived = target.as_posix()
        log.info("Archived previous catalog to %s", archived)
    if changed:
        catalog_path.write_text(new_text, encoding="utf-8")

    latest_month = format_month(max(r["PatchMonthStart"] for r in rows))
    metadata = {
        "GeneratedUtc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "LatestPatchMonth": latest_month,
        "Rows": len(rows),
        "OSVersions": len({r["OSName"] for r in rows}),
        "OSVersionsStillServiced": sorted({r["OSName"] for r in rows if r["OSStillServiced"]}),
        "Source": f"{API_BASE}/updates",
    }
    if changed or not (data_dir / METADATA_FILE).exists():
        (data_dir / METADATA_FILE).write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")

    summary = [f"**Latest patch month:** {latest_month}",
               f"**Catalog:** {len(rows)} releases across {metadata['OSVersions']} Windows versions "
               f"({len(metadata['OSVersionsStillServiced'])} still serviced)"]
    if new_releases:
        summary.append(f"**New releases ({len(new_releases)}):**")
        summary += [f"- {os_name} — {month} — {kb} — {build or 'no build published'}"
                    for os_name, month, build, kb in new_releases[:40]]
        if len(new_releases) > 40:
            summary.append(f"- …and {len(new_releases) - 40} more")
    elif changed:
        summary.append("No new releases; CVE counts were revised by Microsoft.")
    else:
        summary.append("No changes.")
    if archived:
        summary.append(f"**Previous file archived as:** `{archived}`")
    summary_text = "\n".join(summary) + "\n"
    print(summary_text)
    if args.summary_out:
        args.summary_out.write_text(summary_text, encoding="utf-8")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as handle:
            handle.write(summary_text)

    write_github_outputs({"changed": str(changed).lower(), "material": str(material).lower(),
                          "latest_month": latest_month, "new_release_count": len(new_releases)})
    return 0


def read_csv_text(text: str) -> list[dict]:
    return list(csv.DictReader(io.StringIO(text)))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ValidationError as error:
        logging.error("Validation failed, catalog NOT published: %s", error)
        sys.exit(2)
