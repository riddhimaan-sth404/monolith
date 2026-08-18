
rule SUSP_RANSOMWARE_Indicator_Jul20 {
   meta:
      description = "Detects ransomware indicator"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://securelist.com/lazarus-on-the-hunt-for-big-game/97757/"
      date = "2020-07-28"
      score = 60
      hash1 = "52888b5f881f4941ae7a8f4d84de27fc502413861f96ee58ee560c09c11880d6"
      hash2 = "5e78475d10418c6938723f6cfefb89d5e9de61e45ecf374bb435c1c99dd4a473"
      hash3 = "6cb9afff8166976bd62bb29b12ed617784d6e74b110afcf8955477573594f306"
      id = "6036fdfd-8474-5d79-ac75-137ac2efdc77"
   strings:
      $ = "Decrypt.txt" ascii 
      $ = "DecryptFiles.txt" ascii 
      $ = "Decrypt-Files.txt" ascii 
      $ = "DecryptFilesHere.txt" ascii 
      $ = "DECRYPT.txt" ascii 
      $ = "DecryptFiles.txt" ascii 
      $ = "DECRYPT-FILES.txt" ascii 
      $ = "DecryptFilesHere.txt" ascii 
      $ = "DECRYPT_INSTRUCTION.TXT" ascii 
      $ = "FILES ENCRYPTED.txt" ascii 
      $ = "DECRYPT MY FILES" ascii 
      $ = "DECRYPT-MY-FILES" ascii 
      $ = "DECRYPT_MY_FILES" ascii 
      $ = "DECRYPT YOUR FILES" ascii 
      $ = "DECRYPT-YOUR-FILES" ascii 
      $ = "DECRYPT_YOUR_FILES" ascii 
      $ = "DECRYPT FILES.txt" ascii 
condition:
    any of them
}
