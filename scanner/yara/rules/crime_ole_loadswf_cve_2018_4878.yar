
rule crime_ole_loadswf_cve_2018_4878 {
   meta:
      description = "Detects CVE-2018-4878"
      vuln_type = "Remote Code Execution"
      vuln_impact = "Use-after-free"
      affected_versions = "Adobe Flash 28.0.0.137 and earlier versions"
      mitigation0 = "Implement Protected View for Office documents"
      mitigation1 = "Disable Adobe Flash"
      weaponization = "Embedded in Microsoft Office first payloads"
      actor = "Purported North Korean actors"
      reference = "hxxps://www[.]krcert[.]or[.kr/data/secNoticeView.do?bulletin_writing_sequence=26998"
      author = "Vitali Kremez, Flashpoint"
      version = "1.1"
      id = "44797bbc-693b-5fcb-a4a4-4ebf3f4da725"
   strings:
      // EMBEDDED FLASH OBJECT BIN HEADER
      $header = "rdf:RDF" ascii
      // OBJECT APPLICATION TYPE TITLE
      $title = "Adobe Flex" ascii
      // PDB PATH
      $pdb = "F:\\work\\flash\\obfuscation\\loadswf\\src" ascii
      // LOADER STRINGS
      $s0 = "URLRequest" ascii
      $s1 = "URLLoader" ascii
      $s2 = "loadswf" ascii
      $s3 = "myUrlReqest" ascii
condition:
    any of them
}
