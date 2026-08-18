/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2018-01-21
   Identifier: Envrial
   Reference: https://twitter.com/malwrhunterteam/status/953313514629853184
*/

/* Rule Set ----------------------------------------------------------------- */

rule MAL_Envrial_Jan18_1 {
   meta:
      description = "Detects Encrial credential stealer malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/malwrhunterteam/status/953313514629853184"
      date = "2018-01-21"
      hash1 = "9ae3aa2c61f7895ba6b1a3f85fbe36c8697287dc7477c5a03d32cf994fdbce85"
      hash2 = "9edd8f0e22340ecc45c5f09e449aa85d196f3f506ff3f44275367df924b95c5d"
      id = "8be5f0d8-013f-5070-9e19-9ac522c88693"
   strings:
      $x1 = "/Evrial/master/domen" ascii 

      $a1 = "\\Opera Software\\Opera Stable\\Login Data" ascii 
      $a2 = "\\Comodo\\Dragon\\User Data\\Default\\Login Data" ascii 
      $a3 = "\\Google\\Chrome\\User Data\\Default\\Login Data" ascii 
      $a4 = "\\Orbitum\\User Data\\Default\\Login Data" ascii 
      $a5 = "\\Kometa\\User Data\\Default\\Login Data" ascii 

      $s1 = "dlhosta.exe" fullword ascii 
      $s2 = "\\passwords.log" ascii 
      $s3 = "{{ <>h__TransparentIdentifier1 = {0}, Password = {1} }}" fullword ascii 
      $s4 = "files/upload.php?user={0}&hwid={1}" fullword ascii 
condition:
    any of them
}