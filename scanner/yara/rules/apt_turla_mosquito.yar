/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2018-02-22
   Identifier: TurlaMosquito
   Reference: https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf
*/

/* Rule Set ----------------------------------------------------------------- */


rule TurlaMosquito_Mal_1 {
   meta:
      description = "Detects malware sample from Turla Mosquito report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf"
      date = "2018-02-22"
      hash1 = "b295032919143f5b6b3c87ad22bcf8b55ecc9244aa9f6f88fc28f36f5aa2925e"
      id = "1395509a-72f5-56c0-895c-3e9f15829de1"
   strings:
      $s1 = "Pipetp" fullword ascii
      $s2 = "EStOpnabn" fullword ascii
condition:
    any of them
}

rule TurlaMosquito_Mal_2 {
   meta:
      description = "Detects malware sample from Turla Mosquito report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf"
      date = "2018-02-22"
      hash1 = "68c6e9dea81f082601ae5afc41870cea3f71b22bfc19bcfbc61d84786e481cb4"
      hash2 = "05254971fe3e1ca448844f8cfcfb2b0de27e48abd45ea2a3df897074a419a3f4"
      id = "d23d9fe1-26e3-5012-8a88-61ebbc3fbd8f"
   strings:
      $s1 = ".?AVFileNameParseException@ExecuteFile@@" fullword ascii
      $s3 = "no_address" fullword ascii 
      $s6 = "SRRRQP" fullword ascii
      $s7 = "QWVPQQ" fullword ascii
condition:
    any of them
}

rule TurlaMosquito_Mal_3 {
   meta:
      description = "Detects malware sample from Turla Mosquito report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf"
      date = "2018-02-22"
      hash1 = "443cd03b37fca8a5df1bbaa6320649b441ca50d1c1fcc4f5a7b94b95040c73d1"
      id = "c83e0a93-3f8d-572d-ac1a-92fef0b3d3f6"
   strings:
      $x1 = "InstructionerDLL.dll" fullword ascii

      $s1 = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36" fullword ascii 
      $s2 = "/scripts/m/query.php?id=" fullword ascii 
      $s3 = "SELECT * FROM AntiVirusProduct" fullword ascii
      $s4 = "Microsoft Update" fullword ascii 
condition:
    any of them
}




rule TurlaMosquito_Mal_6 {
   meta:
      description = "Detects malware sample from Turla Mosquito report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf"
      date = "2018-02-22"
      hash1 = "b79cdf929d4a340bdd5f29b3aeccd3c65e39540d4529b64e50ebeacd9cdee5e9"
      id = "1c320b60-ec7a-5f87-b871-f55924351f8f"
   strings:
      $a1 = "/scripts/m/query.php?id=" fullword ascii 
      $a2 = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36" fullword ascii 
      $a3 = "GetUserNameW fails" fullword ascii 

      $s1 = "QVSWQQ" fullword ascii
      $s2 = "SRRRQP" fullword ascii
      $s3 = "QSVVQQ" fullword ascii
condition:
    any of them
}

rule APT_TurlaMosquito_MAL_Oct22_1 {
   meta:
      description = "Detects Turla Mosquito malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf"
      date = "2022-10-25"
      score = 80
      hash1 = "6b9e48e3f4873cfb95639d9944fe60e3b056daaa2ea914add14c982e3e11128b"
      hash2 = "b868b674476418bbdffbe0f3d617d1cce4c2b9dae0eaf3414e538376523e8405"
      hash3 = "e7fd14ca45818044690ca67f201cc8cfb916ccc941a105927fc4c932c72b425d"
      id = "f5ad0c0f-81ca-5157-aefb-ead049ada30d"
   strings:
      $s1 = "Logger32.dll" ascii fullword
      $s4 = " executing %u command on drive %martCommand : CWin32ApiErrorExce" ascii 
      $s5 = "Unsupported drive!!!" ascii fullword
      $s7 = "D:\\Build_SVN\\PC_MAGICIAN_4." ascii fullword

      $op1 = { 40 cc 8b 8b 06 cc 55 00 70 8b 10 10 33 51 04 46 04 64 }
      $op2 = { c3 10 e8 50 04 00 cc ff 8d 00 69 8d 75 ff 68 ec 6a 4d }
      $op3 = { e8 64 a1 6e 00 64 a1 c2 04 08 75 40 73 1d 8b ff cc 10 89 cc 8b c3 cc af }
condition:
    any of them
}
