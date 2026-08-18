rule apt_auriga_driver {
   
   meta:
   
      description = "Rule to detect the Auriga driver"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2013-03-13"
      reference = "https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf"
      rule_version = "v1"
      malware_type = "kerneldriver"
      malware_family = "Driver:W32/Auriga"
      actor_type = "APT"
      actor_group = "APT1"
      hash = "207eee627a76449ac6d2ca43338d28087c8b184e7b7b50fdc60a11950c8283ec"
   
   strings:
   
      $s1 = "\\SystemRoot\\System32\\netui.dll" fullword ascii 
      $s2 = "\\SystemRoot\\System32\\drivers\\riodrv32.sys" fullword ascii 
      $s3 = "\\SystemRoot\\System32\\arp.exe" fullword ascii 
      $s4 = "netui.dll" fullword ascii
      $s5 = "riodrv32.sys" fullword ascii 
      $s6 = "\\netui.dll" fullword ascii 
      $s7 = "d:\\drizt\\projects\\auriga\\branches\\stone_~1\\server\\exe\\i386\\riodrv32.pdb" fullword ascii
      $s8 = "\\riodrv32.sys" fullword ascii 
      $s9 = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\riodrv32" fullword ascii 
      $s10 = "\\DosDevices\\rio32drv" fullword ascii 
      $s11 = "e\\Driver\\nsiproxy" fullword ascii 
      $s12 = "(C) S3/Diamond Multimedia Systems. All rights reserved." fullword ascii 
      $s13 = "\\Device\\rio32drv" fullword ascii 
      $s14 = "\\Registry\\Machine\\SOFTWARE\\riodrv" fullword ascii 
      $s15 = "\\Registry\\Machine\\SOFTWARE\\riodrv32" fullword ascii 
   
condition:
    any of them
}