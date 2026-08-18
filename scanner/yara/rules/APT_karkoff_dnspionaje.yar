rule karkoff_dnspionaje {
   
   meta:

      description = "Rule to detect the Karkoff malware"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2019-04-23"
      rule_version = "v1"
      malware_type = "backdoor"
      malware_family = "Backdoor:W32/Karkoff"
      actor_type = "Apt"
      actor_group = "Unknown"
      reference = "https://blog.talosintelligence.com/2019/04/dnspionage-brings-out-karkoff.html"
      hash = "5b102bf4d997688268bab45336cead7cdf188eb0d6355764e53b4f62e1cdf30c"
      
   strings:
   
      $s1 = "DropperBackdoor.Newtonsoft.Json.dll" fullword ascii 
      $s2 = "C:\\Windows\\Temp\\MSEx_log.txt" fullword ascii 
      $s3 = "DropperBackdoor.exe" fullword ascii 
      $s4 = "get_ProcessExtensionDataNames" fullword ascii
      $s5 = "get_ProcessDictionaryKeys" fullword ascii
      $s6 = "https://www.newtonsoft.com/json 0" fullword ascii
      
condition:
    any of them
}
