
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-10-24
   Identifier: Kasper
   Reference: Internal Research
*/

/* Rule Set ----------------------------------------------------------------- */

rule KasperMalware_Oct17_1 {
   meta:
      description = "Detects Kasper Backdoor"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-10-24"
      hash1 = "758bdaf26a0bd309a5458cb4569fe1c789cf5db087880d6d1676dec051c3a28d"
      id = "7201d8ee-50ee-5a5c-a5b8-ee36c78b0d6e"
   strings:
      $x1 = "\\Release\\kasper.pdb" ascii
      $x2 = "C:\\D@oc@um@en@ts a@nd Set@tings\\Al@l Users" ascii 
condition:
    any of them
}
