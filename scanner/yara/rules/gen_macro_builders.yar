
rule SUSP_MalDoc_ExcelMacro {
  meta:
    description = "Detects malicious Excel macro Artifacts"
    author = "James Quinn"
    date = "2020-11-03"
    reference = "YARA Exchange - Undisclosed Macro Builder"
    id = "76806717-a9a8-520e-b6b6-7718eb088de5"
  strings:
    $artifact1 = {5c 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 2e 00 ?? 00 ?? 00}
    $url1 = "http://" ascii 
    $url2 = "https://" ascii 
    $import1 = "URLDownloadToFileA" ascii
    $macro = "xl/macrosheets/"
condition:
    any of them
}
