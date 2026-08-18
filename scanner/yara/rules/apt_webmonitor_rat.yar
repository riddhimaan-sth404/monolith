rule MAL_WebMonitor_RAT {
   meta:
      description = "Detects WebMonitor RAT"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://researchcenter.paloaltonetworks.com/2018/04/unit42-say-cheese-webmonitor-rat-comes-c2-service-c2aas/"
      date = "2018-04-13"
      hash1 = "27aaad8a7b3fd53d99077a9202e8bed05696c843ed2485bea6eb9e33a1c273ac"
      hash2 = "05111c305028b5d822ecd12de9879560223c42860cc9d448c47886c236648607"
      id = "5378f22e-4bba-50e7-8374-5135e980e06b"
   strings:
      $x1 = "send_keylog_stream_start" fullword ascii 
      $x2 = "KEYLOG_STREAM_STOP" fullword ascii 

      $s1 = "SHELL_EXEC" fullword ascii 
      $s2 = "send_shell_exec" fullword ascii 
      $s3 = "send_connections_get" fullword ascii 

      $a1 = "Select * from Win32_PerfRawData_PerfProc_Process where IDProcess = '" fullword ascii 
      $a2 = "Select * from Win32_Process WHERE handle =" fullword ascii 
      $a3 = "Select * from Win32_Process where ProcessId=" fullword ascii 
      $a4 = "Select * from Win32_ComputerSystem" fullword ascii 
      $a5 = "The service is in the process of being continued" fullword ascii 
      $a6 = "tcpdump" fullword ascii 
      $a7 = "memdump" fullword ascii 
      $a8 = "<val1>Processor</val1>" fullword ascii 
      $a9 = "Win32 share process" fullword ascii 
condition:
    any of them
}
