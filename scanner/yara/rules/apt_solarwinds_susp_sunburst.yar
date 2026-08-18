/*

rule SUSP_Solarwinds_SUNBURST_Revoked_Cert {
   meta:
      description = "Detects executables signed with a compromised certificate after 2019 (it doesn't mean that the "
      date = "2020-12-14"
      reference = "https://github.com/fireeye/sunburst_countermeasures/pull/3#issuecomment-747156202"
      score = 50
condition:
    any of them
}
*/

rule LOG_APT_WEBSHELL_Solarwinds_SUNBURST_Report_Webshell_Dec20_2 {
   meta:
      description = "Detects webshell access mentioned in FireEye's SUNBURST report"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.guidepointsecurity.com/supernova-solarwinds-net-webshell-analysis/"
      date = "2020-12-21"
      id = "fb86164d-13de-5357-8f52-c597b51127ff"
   strings:
      $xr1 = /logoimagehandler.ashx[^\n\s]{1,400}clazz=/ ascii
condition:
      $xr1
}
