rule unpacked_shiva_ransomware {

   meta:

      description = "Rule to detect an unpacked sample of Shiva ransomware"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2018-09-05"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/Shiva"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://twitter.com/malwrhunterteam/status/1037424962569732096"
      hash = "299bebcb18e218254960ef96c2e65a4dc1945dcdfe9fc68550022f99a474f56d"
    
   strings:

      $s1 = "c:\\Users\\sys\\Desktop\\v 0.5\\Shiva\\Shiva\\obj\\Debug\\shiva.pdb" fullword ascii
      $s2 = "This email will be as confirmation you are ready to pay for decryption key." fullword ascii 
      $s3 = "Your important files are now encrypted due to a security problem with your PC!" fullword ascii 
      $s4 = "write.php?info=" fullword ascii 
      $s5 = " * Do not try to decrypt your data using third party software, it may cause permanent data loss." fullword ascii 
      $s6 = " * Do not rename encrypted files." fullword ascii 
      $s7 = ".compositiontemplate" fullword ascii 
      $s8 = "You have to pay for decryption in Bitcoins. The price depends on how fast you write to us." fullword ascii 
      $s9 = "\\READ_IT.txt" fullword ascii 
      $s10 = ".lastlogin" fullword ascii 
      $s11 = ".logonxp" fullword ascii 
      $s12 = " * Decryption of your files with the help of third parties may cause increased price" fullword ascii 
      $s13 = "After payment we will send you the decryption tool that will decrypt all your files." fullword ascii 
   
condition:
    any of them
}
