/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-10-03
   Identifier: CMStar Threat Actor
   Reference: https://goo.gl/pTffPA
*/

/* Rule Set ----------------------------------------------------------------- */


rule CMStar_Malware_Sep17 {
   meta:
      description = "Detects CMStar Malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/pTffPA"
      date = "2017-10-03"
      hash1 = "16697c95db5add6c1c23b2591b9d8eec5ed96074d057b9411f0b57a54af298d5"
      id = "d6c9cd7f-06ce-5641-b9b2-c81daf18628d"
   strings:
      $s1 = "UpdateService.tmp" fullword ascii
      $s2 = "StateNum:%d,FileSize:%d" fullword ascii
condition:
    any of them
}
