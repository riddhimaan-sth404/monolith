rule shrug2_ransomware {

   meta:

      description = "Rule to detect the Shrug Ransomware"
      author = "McAfee ATR Team"
      date = "2018-07-12"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/Shrug"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://blogs.quickheal.com/new-net-ransomware-shrug2/"
      hash = "c89833833885bafdcfa1c6ee84d7dbcf2389b85d7282a6d5747da22138bd5c59"
       
   strings:

      $s1 = "C:\\Users\\Gamer\\Desktop\\Shrug2\\ShrugTwo\\ShrugTwo\\obj\\Debug\\ShrugTwo.pdb" fullword ascii
      $s2 = "http://tempacc11vl.000webhostapp.com/" fullword ascii 
      $s3 = "Shortcut for @ShrugDecryptor@.exe" fullword ascii 
      $s4 = "C:\\Users\\" fullword ascii 
      $s5 = "http://clients3.google.com/generate_204" fullword ascii 
      $s6 = "\\Desktop\\@ShrugDecryptor@.lnk" fullword ascii 
   
condition:
    any of them
}
