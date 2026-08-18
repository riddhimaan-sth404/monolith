/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2018-03-10
   Identifier: APT15 Report
   Reference: https://goo.gl/HZ5XMN
*/

/* Rule Set ----------------------------------------------------------------- */


rule APT15_Malware_Mar18_RoyalCli {
   meta:
      description = "Detects malware from APT 15 report by NCC Group"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/HZ5XMN"
      date = "2018-03-10"
      hash1 = "6df9b712ff56009810c4000a0ad47e41b7a6183b69416251e060b5c80cd05785"
      id = "165bfa6c-1a8d-5628-8c35-da4e4a2ae04f"
   strings:
      $s1 = "\\Release\\RoyalCli.pdb" ascii
      $s2 = "%snewcmd.exe" fullword ascii
      $s3 = "Run cmd error %d" fullword ascii
      $s4 = "%s~clitemp%08x.ini" fullword ascii
      $s5 = "run file failed" fullword ascii
      $s6 = "Cmd timeout %d" fullword ascii
      $s7 = "2 %s  %d 0 %d" fullword ascii
condition:
    any of them
}

rule APT15_Malware_Mar18_RoyalDNS {
   meta:
      description = "Detects malware from APT 15 report by NCC Group"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/HZ5XMN"
      date = "2018-03-10"
      hash1 = "bc937f6e958b339f6925023bc2af375d669084e9551fd3753e501ef26e36b39d"
      id = "c2f519db-2750-53ce-ae18-697ea041faaf"
   strings:
      $x1 = "del c:\\windows\\temp\\r.exe /f /q" fullword ascii
      $x2 = "%s\\r.exe" fullword ascii

      $s1 = "rights.dll" fullword ascii
      $s2 = "\"%s\">>\"%s\"\\s.txt" fullword ascii
      $s3 = "Nwsapagent" fullword ascii
      $s4 = "%s\\r.bat" fullword ascii
      $s5 = "%s\\s.txt" fullword ascii
      $s6 = "runexe" fullword ascii
condition:
    any of them
}

rule APT15_Malware_Mar18_BS2005 {
   meta:
      description = "Detects malware from APT 15 report by NCC Group"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/HZ5XMN"
      date = "2018-03-10"
      hash1 = "750d9eecd533f89b8aa13aeab173a1cf813b021b6824bc30e60f5db6fa7b950b"
      id = "700bbe14-d79e-5a35-aab3-31eacd5bd950"
   strings:
      $x1 = "AAAAKQAASCMAABi+AABnhEBj8vep7VRoAEPRWLweGc0/eiDrXGajJXRxbXsTXAcZAABK4QAAPWwAACzWAAByrg==" fullword ascii
      $x2 = "AAAAKQAASCMAABi+AABnhKv3kXJJousn5YzkjGF46eE3G8ZGse4B9uoqJo8Q2oF0AABK4QAAPWwAACzWAAByrg==" fullword ascii

      $a1 = "http://%s/content.html?id=%s" fullword ascii
      $a2 = "http://%s/main.php?ssid=%s" fullword ascii
      $a3 = "http://%s/webmail.php?id=%s" fullword ascii
      $a9 = "http://%s/error.html?tab=%s" fullword ascii

      $s1 = "%s\\~tmp.txt" fullword ascii
      $s2 = "%s /C %s >>\"%s\" 2>&1" fullword ascii
      $s3 = "DisableFirstRunCustomize" fullword ascii
condition:
    any of them
}

rule APT15_Malware_Mar18_MSExchangeTool {
   meta:
      description = "Detects malware from APT 15 report by NCC Group"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/HZ5XMN"
      date = "2018-03-10"
      hash1 = "16b868d1bef6be39f69b4e976595e7bd46b6c0595cf6bc482229dbb9e64f1bce"
      id = "81b826b6-8c2e-5a8a-a626-9515d40dbbb0"
   strings:
      $s1 = "\\Release\\EWSTEW.pdb" ascii
      $s2 = "EWSTEW.exe" fullword ascii 
      $s3 = "Microsoft.Exchange.WebServices.Data" fullword ascii
      $s4 = "tmp.dat" fullword ascii 
      $s6 = "/v or /t is null" fullword ascii 
condition:
    any of them
}

/*
   Identifier: APT15 = Mirage = Ke3chang
   Author: NCCGroup
           Revised by Florian Roth for performance reasons
           see https://gist.github.com/Neo23x0/e3d4e316d7441d9143c7
           > some rules were untightened
   Date: 2018-03-09
   Reference: https://github.com/nccgroup/Royal_APT/blob/master/signatures/apt15.yara
*/

rule clean_apt15_patchedcmd{
   meta:
      author = "Ahmed Zaki"
      description = "This is a patched CMD. This is the CMD that RoyalCli uses."
      sha256 = "90d1f65cfa51da07e040e066d4409dc8a48c1ab451542c894a623bc75c14bf8f"
      id = "c6867ad4-f7f2-5d63-bffd-07599ede635d"
   strings:
      $ = "eisableCMD" ascii 
      $ = "%WINDOWS_COPYRIGHT%" ascii 
      $ = "Cmd.Exe" ascii 
      $ = "Windows Command Processor" ascii 
condition:
      uint16(0) == 0x5A4D and all of them
}

rule malware_apt15_royalcli_1{
   meta:
      description = "Generic strings found in the Royal CLI tool"
      author = "David Cannings"
      sha256 = "6df9b712ff56009810c4000a0ad47e41b7a6183b69416251e060b5c80cd05785"
      id = "432c09bf-3c44-5a2c-ba69-7b4fe7eb43cc"
   strings:
      $ = "%s~clitemp%08x.tmp" fullword ascii
      $ = "%s /c %s>%s" fullword ascii
      $ = "%snewcmd.exe" fullword ascii
      $ = "%shkcmd.exe" fullword ascii
      $ = "%s~clitemp%08x.ini" fullword ascii
      $ = "myRObject" fullword ascii
      $ = "myWObject" fullword ascii
      $ = "2 %s  %d 0 %d\x0D\x0A"
      $ = "2 %s  %d 1 %d\x0D\x0A"
      $ = "%s file not exist" fullword ascii
condition:
      uint16(0) == 0x5A4D and 5 of them
}

rule malware_apt15_royalcli_2{
   meta:
      author = "Nikolaos Pantazopoulos"
      description = "APT15 RoyalCli backdoor"
      id = "d4acfd2d-385d-5063-898e-d339b50733eb"
   strings:
      $string1 = "%shkcmd.exe" fullword ascii
      $string2 = "myRObject" fullword ascii
      $string3 = "%snewcmd.exe" fullword ascii
      $string4 = "%s~clitemp%08x.tmp" fullword ascii
      $string6 = "myWObject" fullword ascii
condition:
      uint16(0) == 0x5A4D and 2 of them
}

/*
rule malware_apt15_bs2005{
   meta:
      author = "Ahmed Zaki"
      md5 = "ed21ce2beee56f0a0b1c5a62a80c128b"
      description = "APT15 bs2005"
   strings:
      $ = "%s&%s&%s&%s" ascii
      $ = "%s\\%s" ascii fullword
      $ = "WarOnPostRedirect" ascii fullword
      $ = "WarnonZoneCrossing" ascii fullword
      $ = "^^^^^" ascii fullword
      $ =  /"?%s\s*"?\s*\/C\s*"?%s\s*>\s*\\?"?%s\\(\w+\.\w+)?"\s*2>&1\s*"?/
      $ ="IEharden" ascii fullword
      $ ="DEPOff" ascii fullword
      $ ="ShownVerifyBalloon" ascii fullword
      $ ="IEHardenIENoWarn" ascii fullword
condition:
    any of them
}
*/

rule malware_apt15_royaldll {
   meta:
      author = "David Cannings"
      description = "DLL implant, originally rights.dll and runs as a service"
      sha256 = "bc937f6e958b339f6925023bc2af375d669084e9551fd3753e501ef26e36b39d"
      id = "26baef92-1055-56dc-b274-e2a6bc05d85b"
   strings:
      /*
      56                push    esi
      B8 A7 C6 67 4E    mov     eax, 4E67C6A7h
      83 C1 02          add     ecx, 2
      BA 04 00 00 00    mov     edx, 4
      57                push    edi
      90                nop
      */
      // JSHash implementation (Justin Sobel's hash algorithm)
      $opcodes_jshash = { B8 A7 C6 67 4E 83 C1 02 BA 04 00 00 00 57 90 }

      /*
      0F B6 1C 03       movzx   ebx, byte ptr [ebx+eax]
      8B 55 08          mov     edx, [ebp+arg_0]
      30 1C 17          xor     [edi+edx], bl
      47                inc     edi
      3B 7D 0C          cmp     edi, [ebp+arg_4]
      72 A4             jb      short loc_10003F31
      */
      // Encode loop, used to "encrypt" data before DNS request
      $opcodes_encode = { 0F B6 1C 03 8B 55 08 30 1C 17 47 3B 7D 0C }

      /*
      68 88 13 00 00    push    5000 # Also seen 3000, included below
      FF D6             call    esi ; Sleep
      4F                dec     edi
      75 F6             jnz     short loc_10001554
      */
      // Sleep loop
      $opcodes_sleep_loop = { 68 (88|B8) (13|0B) 00 00 FF D6 4F 75 F6 }

      // Generic strings
      $ = "Nwsapagent" fullword ascii
      $ = "\"%s\">>\"%s\"\\s.txt"
      $ = "myWObject" fullword ascii
      $ = "del c:\\windows\\temp\\r.exe /f /q"
      $ = "del c:\\windows\\temp\\r.ini /f /q"

condition:
      3 of them
}

rule malware_apt15_royaldll_2 {
   meta:
      author = "Ahmed Zaki"
      sha256 = "bc937f6e958b339f6925023bc2af375d669084e9551fd3753e501ef26e36b39d"
      description = "DNS backdoor used by APT15"
      id = "3bc546a5-38b9-5504-b09e-305ba7bbd6bc"
   strings:
      $= "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost" ascii
      $= "netsvcs" ascii fullword
      $= "%SystemRoot%\\System32\\svchost.exe -k netsvcs" ascii fullword
      $= "SYSTEM\\CurrentControlSet\\Services\\" ascii
      $= "myWObject" ascii
condition:
    any of them
}

rule malware_apt15_exchange_tool {
   meta:
      author = "Ahmed Zaki"
      md5 = "d21a7e349e796064ce10f2f6ede31c71"
      description = "This is a an exchange enumeration/hijacking tool used by an APT 15"
      id = "f07b9537-0741-51c8-a9fa-836430fe4855"
   strings:
      $s1= "subjectname" fullword ascii
      $s2= "sendername" fullword ascii
      $s3= "WebCredentials" fullword ascii
      $s4= "ExchangeVersion" fullword ascii
      $s5= "ExchangeCredentials" fullword ascii
      $s6= "slfilename" fullword ascii
      $s7= "EnumMail" fullword ascii
      $s8= "EnumFolder" fullword ascii
      $s9= "set_Credentials" fullword ascii
      $s18 = "/v or /t is null" ascii 
      $s24 = "2013sp1" ascii 
condition:
      uint16(0) == 0x5A4D and all of them
}

rule malware_apt15_generic {
   meta:
      author = "David Cannings"
      description = "Find generic data potentially relating to AP15 tools"
      id = "4eb50731-22df-5f7a-bf5f-166ef84cf8b5"
   strings:
       // Appears to be from copy/paste code
       $str01 = "myWObject" fullword ascii
       $str02 = "myRObject" fullword ascii

       /*
         6A 02             push    2               ; dwCreationDisposition
         6A 00             push    0               ; lpSecurityAttributes
         6A 00             push    0               ; dwShareMode
         68 00 00 00 C0    push    0C0000000h      ; dwDesiredAccess
         50                push    eax             ; lpFileName
         FF 15 44 F0 00 10 call    ds:CreateFileA
       */
       // Arguments for CreateFileA
       $opcodes01 = { 6A (02|03) 6A 00 6A 00 68 00 00 00 C0 50 FF 15 }
condition:
      2 of them
}
