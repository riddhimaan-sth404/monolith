
rule MAL_CrypRAT_Jan19_1 {
   meta:
      description = "Detects CrypRAT"
      author = "Florian Roth (Nextron Systems)"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      reference = "Internal Research"
      score = 90
      date = "2019-01-07"
      id = "f3063a16-8813-5d6c-9807-6a0725907fb5"
   strings:
      $x1 = "Cryp_RAT" fullword ascii 
condition:
    any of them
}
