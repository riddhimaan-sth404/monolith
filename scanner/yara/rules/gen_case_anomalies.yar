/* This is an extract from THOR's anomaly detection rule set */

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-08-11
   Identifier: PowerShell Anomalies
   Reference: https://twitter.com/danielhbohannon/status/905096106924761088
*/

rule PowerShell_Case_Anomaly {
   meta:
      description = "Detects obfuscated PowerShell hacktools"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/danielhbohannon/status/905096106924761088"
      date = "2017-08-11"
      modified = "2022-06-12"
      score = 70
      id = "41c97d15-c167-5bdd-a8b4-871d14f66fe1"
   strings:
      // first detect 'powershell' keyword case insensitive
      $s1 = "powershell" ascii 
      // define the normal cases
      $sn1 = "powershell" ascii 
      $sn2 = "Powershell" ascii 
      $sn3 = "PowerShell" ascii 
      $sn4 = "POWERSHELL" ascii 
      $sn5 = "powerShell" ascii 
      $sn6 = "PowerShelL" ascii /* PSGet.Resource.psd1 - part of PowerShellGet */
      $sn7 = "PowershelL" ascii /* SCVMM.dll - part of Citrix */

      // PowerShell with \x19\x00\x00
      $a1 = "wershell -e " ascii
      // expected casing
      $an1 = "wershell -e " ascii
      $an2 = "werShell -e " ascii

      // adding a keyword with a sufficent length and relevancy
      $k1 = "-noprofile" fullword ascii 
      // define normal cases
      $kn1 = "-noprofile" ascii 
      $kn2 = "-NoProfile" ascii 
      $kn3 = "-noProfile" ascii 
      $kn4 = "-NOPROFILE" ascii 
      $kn5 = "-Noprofile" ascii 

      $fp1 = "Microsoft Code Signing" ascii fullword
      $fp2 = "Microsoft Corporation" ascii
      $fp3 = "Microsoft.Azure.Commands.ContainerInstance" ascii 
      $fp4 = "# Localized PSGet.Resource.psd1" ascii 
condition:
    any of them
}

rule WScriptShell_Case_Anomaly {
   meta:
      description = "Detects obfuscated wscript.shell commands"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-09-11"
      modified = "2022-06-09"
      score = 60
      id = "d69d932d-1e39-5259-9200-f0227754f49c"
   strings:
      // first detect powershell keyword case insensitive
      $s1 = "WScript.Shell\").Run" ascii
      // define the normal cases
      $sn1 = "WScript.Shell\").Run" ascii
      $sn2 = "wscript.shell\").run" ascii
      $sn3 = "WSCRIPT.SHELL\").RUN" ascii
      $sn4 = "Wscript.Shell\").Run" ascii
      $sn5 = "WScript.shell\").Run" ascii
condition:
    any of them
}
