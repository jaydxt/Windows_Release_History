"""Generate the Power BI (Power Query M) device query from kql/DevicePatchLevel.kql.

The KQL file stays the single source of truth; run this after editing it:
  python scripts/export_powerbi_query.py
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KQL_FILE = ROOT / "kql" / "DevicePatchLevel.kql"
OUT_FILE = ROOT / "powerbi" / "DevicePatchLevel.pq"

TEMPLATE = '''// Power BI > Get data > Blank query > Advanced Editor: paste this whole file.
// Sign in with "Organizational account" (needs Defender "Advanced hunting" read access).
// Generated from kql/DevicePatchLevel.kql by scripts/export_powerbi_query.py - edit the KQL, not this file.
let
    AdvancedHuntingQuery = "{query}",
    Response = Json.Document(Web.Contents("https://api.securitycenter.microsoft.com", [
        RelativePath = "api/advancedqueries/run",
        Headers = [#"Content-Type" = "application/json"],
        Content = Json.FromValue([Query = AdvancedHuntingQuery])
    ])),
    TypeMap = #table({{"Type", "PowerBiType"}}, {{
        {{"Double", Double.Type}}, {{"Int64", Int64.Type}}, {{"Int32", Int32.Type}}, {{"Int16", Int16.Type}},
        {{"UInt64", Number.Type}}, {{"UInt32", Number.Type}}, {{"UInt16", Number.Type}}, {{"Byte", Byte.Type}},
        {{"Single", Single.Type}}, {{"Decimal", Decimal.Type}}, {{"TimeSpan", Duration.Type}},
        {{"DateTime", DateTimeZone.Type}}, {{"String", Text.Type}}, {{"Boolean", Logical.Type}},
        {{"SByte", Logical.Type}}, {{"Guid", Text.Type}}
    }}),
    Schema = Table.FromRecords(Response[Schema]),
    TypedSchema = Table.Join(Table.SelectColumns(Schema, {{"Name", "Type"}}), {{"Type"}}, TypeMap, {{"Type"}}),
    Rows = Table.FromRecords(Response[Results], Schema[Name], MissingField.UseNull),
    Typed = Table.TransformColumnTypes(Rows, Table.ToList(TypedSchema, (c) => {{c{{0}}, c{{2}}}})),
    PatchMonthStart = Table.TransformColumnTypes(Typed, {{{{"PatchMonthStart", type date}}, {{"LastSeen", type datetime}}}})
in
    PatchMonthStart
'''


def main() -> None:
    lines = []
    for line in KQL_FILE.read_text(encoding="utf-8").splitlines():
        if line.lstrip().startswith("//"):
            continue
        line = re.sub(r"\s+//\s.*$", "", line).rstrip()  # trailing comments (URLs have no space after //)
        if line:
            lines.append(line)
    query = "\n".join(lines).replace('"', '""')  # M string escaping
    OUT_FILE.parent.mkdir(exist_ok=True)
    OUT_FILE.write_text(TEMPLATE.format(query=query), encoding="utf-8")
    print(f"Wrote {OUT_FILE.relative_to(ROOT)} ({len(query)} characters of KQL)")


if __name__ == "__main__":
    main()
