rule apt_blackenergy_pdb {
   
   meta:
   
      description = "Rule to detect the BlackEnergy trojan"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2013-02-15"
      rule_version = "v1"
      malware_type = "trojan"
      malware_family = "Trojan:W32/BlackEngergy"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://www.kaspersky.com.au/resource-center/threats/blackenergy"
      hash = "4b2efcda5269f4b80dc417a2b01332185f2fafabd8ba7114fa0306baaab5a72d"
   
   strings:

      $s1 = "msiexec.exe /i \"%s\" %s REBOOT=\"ReallySuppress\"" fullword ascii
      $s2 = "InstallUpdate: CreateProcess failed, Cmdline=%s Error=%d ." fullword ascii 
      $s3 = "Portuguese=Instalando o Tempo de Execu" fullword ascii 
      $s4 = "Initialization: Failed to initialize - Unable to get Upgrade Code." fullword ascii 
      $s5 = "This version of Internet Explorer is not supported.  You should upgrade Internet Explorer to version %s and run setup again.  Se" ascii 
      $s6 = "Initialization: Failed to open %s file, Make sure the file is not used by another process." fullword ascii 
      $s7 = "o %s e execute a configura" fullword ascii 
      $s8 = "Initialization: Failed to initialize - Unable to get Product Version." fullword ascii 
      $s9 = "f:\\CB\\11X_Security\\Acrobat\\Installers\\BootStrapExe_Small\\Release\\Setup.pdb" fullword ascii
      $s10 = "BootStrap.log" fullword ascii 
      $s11 = "ACDownloaderDlg" fullword ascii
      $s12 = "Initialization: Failed to initialize Product - msi key not specified." fullword ascii 
      $s13 = "rio atualizar para o Service Pack %s e executar a instala" fullword ascii 
      $s14 = "\\Msi.dll" fullword ascii 
  
condition:
    any of them
}