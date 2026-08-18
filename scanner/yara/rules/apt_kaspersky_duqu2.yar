/*
	Yara Rule Set
	Author: Mixed - Kasperksy & Florian Roth
	Date: 2015-06-10
	Identifier: Duqu2
*/

/* Rules by Kaspersky ------------------------------------------------------ */

rule APT_apt_duqu2_loaders {
	meta:
		copyright = "Kaspersky Lab"
		description = "Rule to detect Duqu 2.0 samples"
		last_modified = "2015-06-09"
		version = "1.0"
		id = "22db52c2-18e7-537e-a9c5-38ccfd3a0d30"
	strings:
		$a1 = "{AAFFC4F0-E04B-4C7C-B40A-B45DE971E81E}" ascii 
		$a2 = "\\\\.\\pipe\\{AAFFC4F0-E04B-4C7C-B40A-B45DE971E81E}" ascii 
		$a4 = "\\\\.\\pipe\\{AB6172ED-8105-4996-9D2A-597B5F827501}" ascii 
		$a5 = "Global\\{B54E3268-DE1E-4c1e-A667-2596751403AD}" ascii 
		$a8 = "SELECT `Data` FROM `Binary` WHERE `Name`='%s%i'" ascii 
		$a9 = "SELECT `Data` FROM `Binary` WHERE `Name`='CryptHash%i'" ascii 
		$a7 = "SELECT `%s` FROM `%s` WHERE `%s`='CAData%i'" ascii 
		$b1 = "MSI.dll"
		$b2 = "msi.dll"
		$b3 = "StartAction"
		$c1 = "msisvc_32@" ascii 
		$c2 = "PROP=" ascii 
		$c3 = "-Embedding" ascii 
		$c4 = "S:(ML;;NW;;;LW)" ascii 
		$d1 = "NameTypeBinaryDataCustomActionActionSourceTargetInstallExecuteSequenceConditionSequencePropertyValueMicrosoftManufacturer" 
		$d2 = {2E 3F 41 56 3F 24 5F 42 69 6E 64 40 24 30 30 58 55 3F 24 5F 50 6D 66 5F 77 72 61 70 40 50 38 43 4C 52 ?? 40 40 41 45 58 58 5A 58 56 31 40 24 24 24 56 40 73 74 64 40 40 51 41 56 43 4C 52 ?? 40 40 40 73 74 64 40 40}
condition:
    any of them
}

rule APT_apt_duqu2_drivers {
	meta:
		copyright = "Kaspersky Lab"
		description = "Rule to detect Duqu 2.0 drivers"
		last_modified = "2015-06-09"
		version = "1.0"
		id = "714d5151-9f80-582e-a628-1de9d83a072d"
	strings:
		$a1 = "\\DosDevices\\port_optimizer" 
		$a2 = "romanian.antihacker"
		$a3 = "PortOptimizerTermSrv" ascii 
		$a4 = "ugly.gorilla1"
		$b1 = "NdisIMCopySendCompletePerPacketInfo"
		$b2 = "NdisReEnumerateProtocolBindings"
		$b3 = "NdisOpenProtocolConfiguration"
condition:
    any of them
}

/* Action Loader Samples --------------------------------------------------- */

rule Duqu2_Generic1 {
	meta:
		description = "Kaspersky APT Report - Duqu2 Sample - Generic Rule"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/7yKyOj"
		date = "2015-06-10"
		super_rule = 1
		hash0 = "3f9168facb13429105a749d35569d1e91465d313"
		hash1 = "0a574234615fb2382d85cd6d1a250d6c437afecc"
		hash2 = "38447ed1d5e3454fe17699f86c0039f30cc64cde"
		hash3 = "5282d073ee1b3f6ce32222ccc2f6066e2ca9c172"
		hash4 = "edfca3f0196788f7fde22bd92a8817a957c10c52"
		hash5 = "6a4ffa6ca4d6fde8a30b6c8739785f4bd2b5c415"
		hash6 = "00170bf9983e70e8dd4f7afe3a92ce1d12664467"
		hash7 = "32f8689fd18c723339414618817edec6239b18f3"
		hash8 = "f860acec9920bc009a1ad5991f3d5871c2613672"
		hash9 = "413ba509e41c526373f991d1244bc7c7637d3e13"
		hash10 = "29cd99a9b6d11a09615b3f9ef63f1f3cffe7ead8"
		hash11 = "dfe1cb775719b529138e054e7246717304db00b1"
		id = "0e03eda5-d65b-5400-aceb-bc37559d9a6e"
	strings:
		$s0 = "Global\\{B54E3268-DE1E-4c1e-A667-2596751403AD}" fullword ascii 
		$s1 = "SetSecurityDescriptorSacl" fullword ascii /* PEStudio Blacklist: strings */ /* Goodware String - occured 189 times */
		$s2 = "msisvc_32@" fullword ascii 
		$s3 = "CompareStringA" fullword ascii /* PEStudio Blacklist: strings */ /* Goodware String - occured 1392 times */
		$s4 = "GetCommandLineW" fullword ascii /* PEStudio Blacklist: strings */ /* Goodware String - occured 1680 times */
condition:
    any of them
}

rule APT_Kaspersky_Duqu2_procexp {
	meta:
		description = "Kaspersky APT Report - Duqu2 Sample - Malicious MSI"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/7yKyOj"
		date = "2015-06-10"
		hash1 = "2422835716066b6bcecb045ddd4f1fbc9486667a"
		hash2 = "b120620b5d82b05fee2c2153ceaf305807fa9f79"
		hash3 = "288ebfe21a71f83b5575dfcc92242579fb13910d"
		id = "d7fd48d5-2416-5eff-a751-ece09ce27767"
	strings:
		$x1 = "svcmsi_32.dll" fullword ascii 
		$x2 = "msi3_32.dll" fullword ascii 
		$x3 = "msi4_32.dll" fullword ascii 
		$x4 = "MSI.dll" fullword ascii

		$s1 = "SELECT `Data` FROM `Binary` WHERE `Name`='%s%i'" fullword ascii 
		$s2 = "Sysinternals installer" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "Process Explorer" fullword ascii /* PEStudio Blacklist: strings */ /* Goodware String - occured 5 times */
condition:
    any of them
}

rule APT_Kaspersky_Duqu2_SamsungPrint {
	meta:
		description = "Kaspersky APT Report - Duqu2 Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/7yKyOj"
		date = "2015-06-10"
		hash = "ce39f41eb4506805efca7993d3b0b506ab6776ca"
		id = "cc4bc00e-f38b-577f-8f00-637c0549894c"
	strings:
		$s0 = "Installer for printer drivers and applications" fullword ascii /* PEStudio Blacklist: strings */
		$s1 = "msi4_32.dll" fullword ascii 
		$s2 = "HASHVAL" fullword ascii 
		$s3 = "SELECT `%s` FROM `%s` WHERE `%s`='CAData%i'" fullword ascii 
		$s4 = "ca.dll" fullword ascii
		$s5 = "Samsung Electronics Co., Ltd." fullword ascii 
condition:
    any of them
}

rule APT_Kaspersky_Duqu2_msi3_32 {
	meta:
		description = "Kaspersky APT Report - Duqu2 Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/7yKyOj"
		date = "2015-06-10"
		hash = "53d9ef9e0267f10cc10f78331a9e491b3211046b"
		id = "6cbea2e7-f406-57cf-b9c8-9d84b1480035"
	strings:
		$s0 = "ProcessUserAccounts" fullword ascii /* PEStudio Blacklist: strings */
		$s1 = "SELECT `UserName`, `Password`, `Attributes` FROM `CustomUserAccounts`" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "SELECT `UserName` FROM `CustomUserAccounts`" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "SELECT `Data` FROM `Binary` WHERE `Name`='CryptHash%i'" fullword ascii 
		$s4 = "msi3_32.dll" fullword ascii 
		$s5 = "RunDLL" fullword ascii
		$s6 = "MSI Custom Action v3" fullword ascii 
		$s7 = "msi3_32" fullword ascii 
		$s8 = "Operating System" fullword ascii /* PEStudio Blacklist: strings */ /* Goodware String - occured 9203 times */
condition:
    any of them
}
