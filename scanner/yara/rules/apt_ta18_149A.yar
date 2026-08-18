/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2018-05-30
   Identifier: TA-18-149A
   Reference: https://www.us-cert.gov/ncas/alerts/TA18-149A
*/

/* Rule Set ----------------------------------------------------------------- */


rule APT_TA18_149A_Joanap_Sample1 {
   meta:
      description = "Detects malware from TA18-149A report by US-CERT"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.us-cert.gov/ncas/alerts/TA18-149A"
      date = "2018-05-30"
      hash1 = "ea46ed5aed900cd9f01156a1cd446cbb3e10191f9f980e9f710ea1c20440c781"
      id = "a3a4f9a6-367d-5d99-bffb-f4ff03fa4a09"
   strings:
      $x1 = "cmd.exe /q /c net share adnim$" ascii
      $x2 = "\\\\%s\\adnim$\\system32\\%s" fullword ascii
      $s1 = "SMB_Dll.dll" fullword ascii
      $s2 = "%s User or Password is not correct!" fullword ascii
      $s3 = "perfw06.dat" fullword ascii
condition:
    any of them
}

rule APT_TA18_149A_Joanap_Sample2 {
   meta:
      description = "Detects malware from TA18-149A report by US-CERT"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.us-cert.gov/ncas/alerts/TA18-149A"
      date = "2018-05-30"
      hash1 = "077d9e0e12357d27f7f0c336239e961a7049971446f7a3f10268d9439ef67885"
      id = "9f4e6e6c-ee2b-5fa3-bf85-5a1652b38c52"
   strings:
      $s1 = "%SystemRoot%\\system32\\svchost.exe -k Wmmvsvc" fullword ascii
      $s2 = "%SystemRoot%\\system32\\svchost.exe -k SCardPrv" fullword ascii
      $s3 = "%SystemRoot%\\system32\\Wmmvsvc.dll" fullword ascii
      $s4 = "%SystemRoot%\\system32\\scardprv.dll" fullword ascii
condition:
    any of them
}

rule APT_TA18_149A_Joanap_Sample3 {
   meta:
      description = "Detects malware from TA18-149A report by US-CERT"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.us-cert.gov/ncas/alerts/TA18-149A"
      date = "2018-05-30"
      hash1 = "a1c483b0ee740291b91b11e18dd05f0a460127acfc19d47b446d11cd0e26d717"
      id = "1c2551bc-01dd-5b30-a4cc-703a868cde73"
   strings:
      $s1 = "mssvcdll.dll" fullword ascii
      $s2 = "https://www.google.com/index.html" fullword ascii
      $s3 = "LOGINDLG" fullword ascii 
      $s4 = "rundll" fullword ascii
      $s5 = "%%s\\%%s%%0%dd.%%s" fullword ascii
      $s6 = "%%s\\%%s%%0%dd" fullword ascii
condition:
    any of them
}
