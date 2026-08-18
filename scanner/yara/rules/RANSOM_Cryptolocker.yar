rule CryptoLocker_set1
{

	meta:

		description = "Detection of Cryptolocker Samples"
		author = "Christiaan Beek, Christiaan_Beek@McAfee.com"
		date = "2014-04-13"
		rule_version = "v1"
	    malware_type = "ransomware"
	    malware_family = "Ransom:W32/Cryptolocker"
	    actor_type = "Cybercrime"
	    actor_group = "Unknown"
		
		
	strings:

		$string0 = "static"
		$string1 = " kscdS"
		$string2 = "Romantic"
		$string3 = "CompanyName" ascii 
		$string4 = "ProductVersion" ascii 
		$string5 = "9%9R9f9q9"
		$string6 = "IDR_VERSION1" ascii 
		$string7 = "  </trustInfo>"
		$string8 = "LookFor" ascii 
		$string9 = ":n;t;y;"
		$string10 = "        <requestedExecutionLevel level"
		$string11 = "VS_VERSION_INFO" ascii 
		$string12 = "2.0.1.0" ascii 
		$string13 = "<assembly xmlns"
		$string14 = "  <trustInfo xmlns"
		$string15 = "srtWd@@"
		$string16 = "515]5z5"
		$string17 = "C:\\lZbvnoVe.exe" ascii 

condition:
		12 of ($string*)
}

rule CryptoLocker_rule2
{

	meta:

		description = "Detection of CryptoLocker Variants"
		author = "Christiaan Beek, Christiaan_Beek@McAfee.com"
		date = "2014-04-14"
		rule_version = "v1"
	    malware_type = "ransomware"
	    malware_family = "Ransom:W32/Cryptolocker"
	    actor_type = "Cybercrime"
	    actor_group = "Unknown"

	strings:

		$string0 = "2.0.1.7" ascii 
		$string1 = "    <security>"
		$string2 = "Romantic"
		$string3 = "ProductVersion" ascii 
		$string4 = "9%9R9f9q9"
		$string5 = "IDR_VERSION1" ascii 
		$string6 = "button"
		$string7 = "    </security>"
		$string8 = "VFileInfo" ascii 
		$string9 = "LookFor" ascii 
		$string10 = "      </requestedPrivileges>"
		$string11 = " uiAccess"
		$string12 = "  <trustInfo xmlns"
		$string13 = "last.inf"
		$string14 = " manifestVersion"
		$string15 = "FFFF04E3" ascii 
		$string16 = "3,31363H3P3m3u3z3"

condition:
		12 of ($string*)
}


