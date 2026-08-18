
rule SUSP_BAT_OBFUSC_Jul24_1 {
   meta:
      description = "Detects indicators of obfuscation in Windows Batch files"
      author = "Florian Roth"
      reference = "https://x.com/0xToxin/status/1811656147943752045"
      date = "2024-07-12"
      score = 70
      id = "801e7efc-2c31-5590-afcd-9e11072c9c65"
   strings:
      $s1 = "&&set "
condition:
    any of them
}

rule SUSP_BAT_OBFUSC_Jul24_2 {
   meta:
      description = "Detects indicators of obfuscation in Windows Batch files"
      author = "Florian Roth"
      reference = "https://x.com/0xToxin/status/1811656147943752045"
      date = "2024-07-12"
      score = 70
      id = "999cd365-2862-5618-b0b6-ee45dea1e9cf"
   strings:
      $s1 = "&&set "
condition:
    any of them
}

rule SUSP_BAT_OBFUSC_Jul24_3 {
   meta:
      description = "Detects indicators of obfuscation in Windows Batch files"
      author = "Florian Roth"
      reference = "https://x.com/0xToxin/status/1811656147943752045"
      date = "2024-07-12"
      score = 70
      id = "a484ed03-8588-55e7-9674-b1208e14eb3f"
   strings:
      $s1 = "% \\\\%" // part of the UNC path for the SMB connection
      // It detects the set pattern with a single character value in front of the %%
      // we use ?? to wildcard the character
      // =?&&set 
      $s2 = { 3D ?? 26 26 73 65 74 20 } 
condition:
    any of them
}
