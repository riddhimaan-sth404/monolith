

rule MAL_PE_Type_BabyShark_Loader {
   meta:
      description = "Detects PE Type babyShark loader mentioned in February 2019 blog post by PaloAltNetworks"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://unit42.paloaltonetworks.com/new-babyshark-malware-targets-u-s-national-security-think-tanks/"
      date = "2019-02-24"
      hash1 = "6f76a8e16908ba2d576cf0e8cdb70114dcb70e0f7223be10aab3a728dc65c41c"
      id = "141e7a67-7930-5fd8-ac91-5d31b99e4ff3"
   strings:
      $x1 = "reg add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Command Processor\" /v AutoRun /t REG_SZ /d \"%s\" /f" fullword ascii
      $x2 = /mshta\.exe http:\/\/[a-z0-9\.\/]{5,30}\.hta/

      $xc1 = { 57 69 6E 45 78 65 63 00 6B 65 72 6E 65 6C 33 32
               2E 44 4C 4C 00 00 00 00 } /* WinExec kernel32.DLL */
condition:
    any of them
}

rule APT_NK_BabyShark_KimJoingRAT_Apr19_1 {
   meta:
      description = "Detects BabyShark KimJongRAT"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://unit42.paloaltonetworks.com/babyshark-malware-part-two-attacks-continue-using-kimjongrat-and-pcrat/"
      date = "2019-04-27"
      hash1 = "d50a0980da6297b8e4cec5db0a8773635cee74ac6f5c1ff18197dfba549f6712"
      id = "c6bd1e1a-68f2-5a2d-a159-b16ea0d33987"
   strings:
      $x1 = "%s\\Microsoft\\ttmp.log" fullword ascii 

      $a1 = "logins.json" fullword ascii

      $s1 = "https://www.google.com/accounts/servicelogin" fullword ascii
      $s2 = "https://login.yahoo.com/config/login" fullword ascii
      $s3 = "SELECT id, hostname, httpRealm, formSubmitURL, usernameField, passwordField, encryptedUsername, encryptedPassword FROM moz_login" ascii
      $s4 = "\\mozsqlite3.dll" ascii
      $s5 = "SMTP Password" fullword ascii
      $s6 = "Yandex\\YandexBrowser\\User Data\\Default\\Login Data" fullword ascii
condition:
    any of them
}
