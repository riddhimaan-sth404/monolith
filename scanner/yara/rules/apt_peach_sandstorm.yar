rule APT_MAL_FalseFont_Backdoor_Jan24 {
   meta:
      description = "Detects FalseFont backdoor, related to Peach Sandstorm APT"
      author = "X__Junior, Jonathan Peters"
      date = "2024-01-11"
      reference = "https://twitter.com/MsftSecIntel/status/1737895710169628824"
      hash = "364275326bbfc4a3b89233dabdaf3230a3d149ab774678342a40644ad9f8d614"
      score = 80
      id = "b6a3efff-2abf-5ac1-9a2b-c7b30b51f92c"
   strings:
      $x1 = "Agent.Core.WPF.App" ascii
      $x2 = "3EzuNZ0RN3h3oV7rzILktSHSaHk+5rtcWOr0mlA1CUA=" ascii //AesIV
      $x3 = "viOIZ9cX59qDDjMHYsz1Yw==" ascii // AesKey

      $sa1 = "StopSendScreen" ascii 
      $sa2 = "Decryption failed :(" ascii 

      $sb1 = "{0}     {1}     {2}     {3}" ascii 
      $sb2 = "\\BraveSoftware\\Brave-Browser\\User Data\\" ascii 
      $sb3 = "select * from logins" ascii 
      $sb4 = "Loginvault.db" ascii 
      $sb5 = "password_value" ascii 
condition:
      uint16(0) == 0x5a4d
      and (
         1 of ($x*)
         or all of ($sa*)
         or all of ($sb*)
         or ( 1 of ($sa*) and 4 of ($sb*) )
      )
}
