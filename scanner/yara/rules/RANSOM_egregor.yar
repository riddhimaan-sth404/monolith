
rule ransom_egregor {

   meta:
      description = "Detect Egregor ransomware"
      author = "Thomas Roccia | McAfee ATR team"
      reference = "https://bazaar.abuse.ch/sample/004a2dc3ec7b98fa7fe6ae9c23a8b051ec30bcfcd2bc387c440c07ff5180fe9a/"
      date = "2020-10-28"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom/Egregor"
      actor_type = "Cybercrime"
      actor_group = "egregor"
      hash = "5f9fcbdf7ad86583eb2bbcaa5741d88a"

   strings:
      $p1 = "ewdk.pdb" fullword ascii
      $p2 = "testbuild.pdb" fullword ascii

      $s1 = "M:\\" ascii
      $s2 = "1z1M9U9" fullword ascii 
      $s3 = "C:\\Logmein\\{888-8888-9999}\\Logmein.log" fullword ascii 

condition:
    any of them
}
