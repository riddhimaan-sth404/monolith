
rule MAL_Ryuk_Ransomware {
   meta:
      description = "Detects strings known from Ryuk Ransomware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://research.checkpoint.com/ryuk-ransomware-targeted-campaign-break/"
      date = "2018-12-31"
      hash1 = "965884f19026913b2c57b8cd4a86455a61383de01dabb69c557f45bb848f6c26"
      hash2 = "b8fcd4a3902064907fb19e0da3ca7aed72a7e6d1f94d971d1ee7a4d3af6a800d"
      id = "25d40631-4158-5d3d-913e-a2f1233489e0"
   strings:
      $x1 = "/v \"svchos\" /f" fullword ascii
      $x2 = "\\Documents and Settings\\Default User\\finish" ascii 
      $x3 = "\\users\\Public\\finish" ascii 
      $x4 = "lsaas.exe" fullword ascii 
      $x5 = "RyukReadMe.txt" fullword ascii 
condition:
    any of them
}
