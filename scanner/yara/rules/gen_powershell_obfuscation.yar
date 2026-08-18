/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-06-22
   Identifier: ISESteroids
   Reference: https://twitter.com/danielhbohannon/status/877953970437844993
*/

/* Rule Set ----------------------------------------------------------------- */

rule PowerShell_ISESteroids_Obfuscation {
   meta:
      description = "Detects PowerShell ISESteroids obfuscation"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/danielhbohannon/status/877953970437844993"
      date = "2017-06-23"
      id = "d686c4de-28fd-5d77-91d4-dde5661b75cd"
   strings:
      $x1 = "/\\/===\\__" ascii
      $x2 = "${__/\\/==" ascii
      $x3 = "Catch { }" fullword ascii
      $x4 = "\\_/=} ${_" ascii
condition:
      2 of them
}

rule SUSP_Obfuscted_PowerShell_Code {
   meta:
      description = "Detects obfuscated PowerShell Code"
      date = "2018-12-13"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/silv0123/status/1073072691584880640"
      id = "e2d8fc9e-ce2b-5118-8305-0d5839561d4f"
   strings:
      $s1 = "').Invoke(" ascii
      $s2 = "(\"{1}{0}\"" ascii
      $s3 = "{0}\" -f" ascii
condition:
    any of them
}

rule SUSP_PowerShell_Caret_Obfuscation_2 {
   meta:
      description = "Detects powershell keyword obfuscated with carets"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2019-07-20"
      id = "976e261a-029c-5703-835f-a235c5657471"
   strings:
      $r1 = /p[\^]?o[\^]?w[\^]?e[\^]?r[\^]?s[\^]?h[\^]?e[\^]?l\^l/ ascii fullword
      $r2 = /p\^o[\^]?w[\^]?e[\^]?r[\^]?s[\^]?h[\^]?e[\^]?l[\^]?l/ ascii fullword
condition:
      1 of them
}

rule SUSP_OBFUSC_PowerShell_True_Jun20_1 {
   meta:
      description = "Detects indicators often found in obfuscated PowerShell scripts. Note: This detection is based on common characteristics typically associated with the mentioned threats, must be considered a clue and does not conclusively prove maliciousness."
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/corneacristian/mimikatz-bypass/"
      date = "2020-06-27"
      score = 75
      id = "e9bb870b-ad72-57d3-beff-2f84a81490eb"
   strings:
      $ = "${t`rue}" ascii 
      $ = "${tr`ue}" ascii 
      $ = "${tru`e}" ascii 
      $ = "${t`ru`e}" ascii 
      $ = "${tr`u`e}" ascii 
      $ = "${t`r`ue}" ascii 
      $ = "${t`r`u`e}" ascii 
condition:
    any of them
}
