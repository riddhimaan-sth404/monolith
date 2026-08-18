
rule BluenoroffPoS_DLL {
   meta:
      description = "Bluenoroff POS malware - hkp.dll"
      author = "http://blog.trex.re.kr/"
      reference = "http://blog.trex.re.kr/3?category=737685"
      date = "2018-06-07"
      id = "d2b34b50-c7eb-5852-ba5d-734dd5038c2e"
   strings:
      $dll = "ksnetadsl.dll" ascii fullword 
      $exe = "xplatform.exe" ascii fullword 
      $agent = "Nimo Software HTTP Retriever 1.0" ascii 
      $log_file = "c:\\windows\\temp\\log.tmp" ascii 
      $base_addr = "%d-BaseAddr:0x%x" ascii 
      $func_addr = "%d-FuncAddr:0x%x" ascii 
      $HF_S = "HF-S(%d)" ascii 
      $HF_T = "HF-T(%d)" ascii 
condition:
      5 of them
}
