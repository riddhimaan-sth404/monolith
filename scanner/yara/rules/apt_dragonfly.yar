/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-09-12
   Identifier: DragonFly
   Reference: https://www.symantec.com/connect/blogs/dragonfly-western-energy-sector-targeted-sophisticated-attack-group
*/

/* Rule Set ----------------------------------------------------------------- */



rule DragonFly_APT_Sep17_1 {
   meta:
      description = "Detects malware from DrqgonFly APT report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.symantec.com/connect/blogs/dragonfly-western-energy-sector-targeted-sophisticated-attack-group"
      date = "2017-09-12"
      hash1 = "fc54d8afd2ce5cb6cc53c46783bf91d0dd19de604308d536827320826bc36ed9"
      id = "d219a54e-cb76-5c56-b64c-5019e811eeb1"
   strings:
      $s1 = "\\Update\\Temp\\ufiles.txt" ascii 
      $s2 = "%02d.%02d.%04d %02d:%02d" fullword ascii 
      $s3 = "*pass*.*" fullword ascii 
condition:
    any of them
}

rule DragonFly_APT_Sep17_2 {
   meta:
      description = "Detects malware from DrqgonFly APT report"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.symantec.com/connect/blogs/dragonfly-western-energy-sector-targeted-sophisticated-attack-group"
      date = "2017-09-12"
      modified = "2023-01-06"
      hash1 = "178348c14324bc0a3e57559a01a6ae6aa0cb4013aabbe324b51f906dcf5d537e"
      id = "e64f121d-a628-54b5-88f3-96eea388c155"
   strings:
      $s1 = "\\AppData\\Roaming\\Opera Software\\Opera Stable\\Login Data" ascii 
      $s2 = "C:\\Users\\Public\\Log.txt" fullword ascii 
      $s3 = "SELECT hostname, encryptedUsername, encryptedPassword FROM moz_logins" fullword ascii 
      $s4 = "***************** Mozilla Firefox ****************" fullword ascii 
      $s5 = "********************** Opera *********************" fullword ascii 
      $s6 = "\\AppData\\Local\\Microsoft\\Credentials\\" ascii 
      $s7 = "\\Appdata\\Local\\Google\\Chrome\\User Data\\Default\\" ascii 
      $s8 = "**************** Internet Explorer ***************" fullword ascii 
condition:
    any of them
}

rule DragonFly_APT_Sep17_3 {
   meta:
      description = "Detects malware from DrqgonFly APT report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.symantec.com/connect/blogs/dragonfly-western-energy-sector-targeted-sophisticated-attack-group"
      date = "2017-09-12"
      hash1 = "b051a5997267a5d7fa8316005124f3506574807ab2b25b037086e2e971564291"
      id = "4eafd732-80bc-5f50-bf0d-096df4d35d61"
   strings:
      $s1 = "kernel64.dll" fullword ascii
      $s2 = "ws2_32.dQH" fullword ascii
      $s3 = "HGFEDCBADCBA" fullword ascii
      $s4 = "AWAVAUATWVSU" fullword ascii
condition:
    any of them
}

rule DragonFly_APT_Sep17_4 {
   meta:
      description = "Detects malware from DrqgonFly APT report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.symantec.com/connect/blogs/dragonfly-western-energy-sector-targeted-sophisticated-attack-group"
      date = "2017-09-12"
      hash1 = "2f159b71183a69928ba8f26b76772ec504aefeac71021b012bd006162e133731"
      id = "dbc0eebf-fc81-5a0b-b2e0-129d0b40b6f7"
   strings:
      $s1 = "screen.exe" fullword ascii 
      $s2 = "PlatformInvokeUSER32" fullword ascii
      $s3 = "GetDesktopImageF" fullword ascii
      $s4 = "PlatformInvokeGDI32" fullword ascii
      $s5 = "GetDesktopImage" fullword ascii
      $s6 = "Too many arguments, going to store in current dir" fullword ascii 
condition:
    any of them
}
