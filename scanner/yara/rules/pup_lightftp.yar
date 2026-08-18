
rule LightFTP_fftp_x86_64 {
	meta:
		description = "Detects a light FTP server"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/hfiref0x/LightFTP"
		date = "2015-05-14"
		hash1 = "989525f85abef05581ccab673e81df3f5d50be36"
		hash2 = "5884aeca33429830b39eba6d3ddb00680037faf4"
		score = 50
		id = "9b62e990-1d8b-5d30-bb58-1f7f12552834"
	strings:
		$s1 = "fftp.cfg" fullword ascii 
		$s2 = "220 LightFTP server v1.0 ready" fullword ascii
		$s3 = "*FTP thread exit*" fullword ascii 
		$s4 = "PASS->logon successful" fullword ascii
		$s5 = "250 Requested file action okay, completed." fullword ascii
condition:
    any of them
}

rule LightFTP_Config {
	meta:
		description = "Detects a light FTP server - config file"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/hfiref0x/LightFTP"
		date = "2015-05-14"
		hash = "ce9821213538d39775af4a48550eefa3908323c5"
		id = "02ee1d04-1425-5dfd-9b9a-cd378aeda311"
	strings:
		$s2 = "maxusers=" ascii 
		$s6 = "[ftpconfig]" fullword ascii 
		$s8 = "accs=readonly" fullword ascii 
		$s9 = "[anonymous]" fullword ascii 
		$s10 = "accs=" fullword ascii 
		$s11 = "pswd=" fullword ascii 
condition:
    any of them
}