rule HKTL_EDR_Freeze_Sep25_2 {
   meta:
      description = "Detects EDR-Freeze hacktool"
      author = "Florian Roth"
      reference = "https://github.com/TwoSevenOneT/EDR-Freeze"
      date = "2025-09-30"
      score = 80
      hash1 = "193ca17f574fa5e23866560170425f83696f78e83dabd7e831dd7827a69283fd"
      hash2 = "36a17919a97732f1ddc31b421c6ebb0c535924f895d7caaff04a5da908c42f76"
      hash3 = "394b768bfd3506a9ee6b7bbe6f87c40fb23c28f7919a2a9eb333b27db635eafe"
      hash4 = "a8ec07f006a9068ce5f068b3bb61b0649481b6b26203b8eb4308c53ff1d1bf8d"
      hash5 = "d485017fb20c5a8fe38a6dbf896d4cbce485ff53a6cfe0e1440a1818b2d303ee"
      hash6 = "d989ebd417e6fae60a544e43bfc0ee63f5d9352ce0059b95ed4e7e18efbc5d0b"
      hash7 = "e2b2dd0984e52112965392471f6a09020eb8380aa53d48d2fb4dd3aaa7edae9b"
      id = "e3fd5815-71c4-5510-bfb4-82203d81cc78"
   strings:
      $x1 = "EDR-Freeze.exe <TargetPID> <SleepTime>" ascii fullword
      $x2 = "Successfully created PPL process with PID:" ascii fullword
      $x3 = "\\EDR-Freeze.pdb" ascii

      $sa1 = "C:\\Windows\\System32\\WerFaultSecure.exe" ascii fullword /* String occurs 2 times in goodware */
      $sa2 = "Failed to create dump files: " ascii fullword

      $sb1 = " /encfile" ascii fullword
      $sb2 = " /pid" ascii fullword
      $sb3 = " /tid" ascii fullword
      $sb4 = " /cancel" ascii fullword
condition:
    any of them
}
