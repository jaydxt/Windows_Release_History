// Power BI > Get data > Blank query > Advanced Editor: paste this whole file.
// Data source credentials: Anonymous (public GitHub repository).
let
    Source = Csv.Document(
        Web.Contents("https://raw.githubusercontent.com", [
            RelativePath = "jaydxt/Windows_Release_History/master/data/Windows_Security_Releases.csv"
        ]),
        [Delimiter = ",", Encoding = 65001, QuoteStyle = QuoteStyle.Csv]
    ),
    Promoted = Table.PromoteHeaders(Source, [PromoteAllScalars = true]),
    Typed = Table.TransformColumnTypes(Promoted, {
        {"OSFamily", type text}, {"OSName", type text}, {"Platform", type text},
        {"BuildNumber", Int64.Type}, {"Revision", Int64.Type}, {"FullBuild", type text},
        {"KB", type text}, {"UpdateType", type text}, {"PatchMonth", type text},
        {"PatchMonthStart", type date}, {"ReleaseDate", type date}, {"ReleaseRank", Int64.Type},
        {"IsLatestForOS", type logical}, {"CVECount", Int64.Type}, {"CriticalCVECount", Int64.Type},
        {"ExploitedCVECount", Int64.Type}, {"CVEsReleasedSince", Int64.Type},
        {"CriticalCVEsReleasedSince", Int64.Type}, {"ExploitedCVEsReleasedSince", Int64.Type},
        {"OSLatestPatchMonth", type text}, {"OSLatestFullBuild", type text},
        {"OSStillServiced", type logical}, {"MsrcDocumentId", type text}
    }, "en-US")
in
    Typed
