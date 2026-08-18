
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-09-27
   Identifier: Xtreme / XRat
   Reference: Internal Research
*/

/* Rule Set ----------------------------------------------------------------- */


rule Xtreme_Sep17_1 {
   meta:
      description = "Detects XTREME sample analyzed in September 2017"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-09-27"
      hash1 = "93c89044e8850721d39e935acd3fb693de154b7580d62ed460256cabb75599a6"
      id = "7517e237-9cad-5619-9028-4c7ab5463040"
   strings:
      $x1 = "ServerKeyloggerU" fullword ascii
      $x2 = "TServerKeylogger" fullword ascii
      $x3 = "XtremeKeylogger" fullword ascii 
      $x4 = "XTREMEBINDER" fullword ascii 

      $s1 = "shellexecute=" fullword ascii 
      $s2 = "[Execute]" fullword ascii 
      $s3 = ";open=RECYCLER\\S-1-5-21-1482476501-3352491937-682996330-1013\\" ascii 
condition:
    any of them
}

rule Xtreme_Sep17_2 {
   meta:
      description = "Detects XTREME sample analyzed in September 2017"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-09-27"
      hash1 = "f8413827c52a5b073bdff657d6a277fdbfda29d909b4247982f6973424fa2dcc"
      id = "b4878e80-54dc-5a16-9129-ddf2b1a5d287"
   strings:
      $s1 = "Spy24.exe" fullword ascii 
      $s2 = "Remote Service Application" fullword ascii 
condition:
    any of them
}

rule Xtreme_Sep17_3 {
   meta:
      description = "Detects XTREME sample analyzed in September 2017"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-09-27"
      hash1 = "f540a4cac716438da0c1c7b31661abf35136ea69b963e8f16846b96f8fd63dde"
      id = "160673ea-b263-520a-a1c1-da0f3e920f12"
   strings:
      $s2 = "Keylogg" fullword ascii
      $s4 = "XTREME" fullword ascii 
condition:
    any of them
}


