rule Ransom_Maze {
   
   meta:
   
      description = "Detecting MAZE Ransomware"
      author = "McAfee ATR"
      date = "2020-04-19"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/Maze"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      hash = "5badaf28bde6dcf77448b919e2290f95cd8d4e709ef2d699aae21f7bae68a76c"

   strings:

      $x1 = "process call create \"cmd /c start %s\"" fullword ascii
      $s1 = "%spagefile.sys" fullword ascii 
      $s2 = "%sswapfile.sys" fullword ascii 
      $s3 = "%shiberfil.sys" fullword ascii 
      $s4 = "\\wbem\\wmic.exe" fullword ascii 
      $s5 = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko" fullword ascii
      $s6 = "NO MUTEX | " fullword ascii 
      $s7 = "--nomutex" fullword ascii 
      $s8 = ".Logging enabled | Maze" fullword ascii 
      $s9 = "DECRYPT-FILES.txt" fullword ascii 

      $op0 = { 85 db 0f 85 07 ff ff ff 31 c0 44 44 44 44 5e 5f }
      $op1 = { 66 90 89 df 39 ef 89 fb 0f 85 64 ff ff ff eb 5a }
      $op2 = { 56 e8 34 ca ff ff 83 c4 08 55 e8 0b ca ff ff 83 }

condition:
    any of them
}

