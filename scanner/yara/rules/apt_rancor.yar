/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2018-06-26
   Identifier: RANCOR
   Reference: https://researchcenter.paloaltonetworks.com/2018/06/unit42-rancor-targeted-attacks-south-east-asia-using-plaintee-ddkong-malware-families/
*/

/* Rule Set ----------------------------------------------------------------- */


rule APT_RANCOR_JS_Malware {
   meta:
      description = "Rancor Malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://researchcenter.paloaltonetworks.com/2018/06/unit42-rancor-targeted-attacks-south-east-asia-using-plaintee-ddkong-malware-families/"
      date = "2018-06-26"
      hash1 = "1dc5966572e94afc2fbcf8e93e3382eef4e4d7b5bc02f24069c403a28fa6a458"
      id = "83dd9567-199e-511c-8c9a-96422bd793e7"
   strings:
      $x1 = ",0,0 >%SystemRoot%\\system32\\spool\\drivers\\color\\fb.vbs\",0,0" fullword ascii
      $x2 = "CreateObject(\"Wscript.Shell\").Run \"explorer.exe \"\"http" ascii
      $x3 = "CreateObject(\"Wscript.Shell\").Run \"schtasks /create" ascii
condition:
    any of them
}

rule APT_RANCOR_PLAINTEE_Variant {
   meta:
      description = "Detects PLAINTEE malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://researchcenter.paloaltonetworks.com/2018/06/unit42-rancor-targeted-attacks-south-east-asia-using-plaintee-ddkong-malware-families/"
      date = "2018-06-26"
      hash1 = "6aad1408a72e7adc88c2e60631a6eee3d77f18a70e4eee868623588612efdd31"
      hash2 = "bcd37f1d625772c162350e5383903fe8dbed341ebf0dc38035be5078624c039e"
      id = "f5b68079-0517-504d-a45f-f6ced532db82"
   strings:
      $s1 = "payload.dat" fullword ascii
      $s3 = "temp_microsoft_test.txt" fullword ascii
      $s4 = "reg add %s /v %s /t REG_SZ /d \"%s\"" fullword ascii
      $s6 = "%s %s,helloworld2" fullword ascii
      $s9 = "%s \\\"%s\\\",helloworld" fullword ascii
      $s16 = "recv plugin type %s size:%d" fullword ascii
condition:
    any of them
}



