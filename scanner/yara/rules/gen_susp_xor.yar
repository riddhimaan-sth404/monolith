/* requires YARA 3.8 or higher */

rule SUSP_XORed_URL_In_EXE {
   meta:
      description = "Detects an XORed URL in an executable"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/stvemillertime/status/1237035794973560834"
      date = "2020-03-09"
      modified = "2022-09-16"
      score = 50
      id = "f83991c8-f2d9-5583-845a-d105034783ab"
   strings:
      $s1 = "http://" 
      $s2 = "https://" 
      $f1 = "http://" ascii
      $f2 = "https://" ascii

      $fp01 = "3Com Corporation" ascii /* old driver */
      $fp02 = "bootloader.jar" ascii /* DeepGit */
      $fp03 = "AVAST Software" ascii 
      $fp04 = "smartsvn" ascii fullword
      $fp05 = "Avira Operations GmbH" ascii fullword
      $fp06 = "Perl Dev Kit" ascii fullword
      $fp07 = "Digiread" ascii fullword
      $fp08 = "Avid Editor" ascii fullword
      $fp09 = "Digisign" ascii fullword
      $fp10 = "Microsoft Corporation" ascii fullword
      $fp11 = "Microsoft Code Signing" ascii 
      $fp12 = "XtraProxy" ascii fullword
      $fp13 = "A Sophos Company" ascii 
      $fp14 = "http://crl3.digicert.com/" ascii
      $fp15 = "http://crl.sectigo.com/SectigoRSACodeSigningCA.crl" ascii
      $fp16 = "HitmanPro.Alert" ascii fullword
condition:
    any of them
}

