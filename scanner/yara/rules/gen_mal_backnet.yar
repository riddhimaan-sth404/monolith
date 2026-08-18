
rule MAL_BackNet_Nov18_1 {
   meta:
      description = "Detects BackNet samples"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/valsov/BackNet"
      date = "2018-11-02"
      hash1 = "4ce82644eaa1a00cdb6e2f363743553f2e4bd1eddb8bc84e45eda7c0699d9adc"
      id = "f8575c5a-710d-5e97-91c1-5db454c6baf4"
   strings:
      $s1 = "ProcessedByFody" fullword ascii
      $s2 = "SELECT * FROM AntivirusProduct" fullword ascii 
      $s3 = "/C netsh wlan show profile" ascii 
      $s4 = "browsertornado" fullword ascii 
      $s5 = "Current user is administrator" fullword ascii 
      $s6 = "/C choice /C Y /N /D Y /T 4 & Del" ascii 
      $s7 = "ThisIsMyMutex-2JUY34DE8E23D7" ascii 
condition:
    any of them
}
