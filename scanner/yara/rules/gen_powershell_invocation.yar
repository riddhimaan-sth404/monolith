
rule PowerShell_Susp_Parameter_Combo {
   meta:
      description = "Detects PowerShell invocation with suspicious parameters"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/uAic1X"
      date = "2017-03-12"
      modified = "2025-12-16"
      score = 60
      id = "17c707f3-7f51-5772-9874-a96c220960a7"
   strings:
      /* Encoded Command */
      $sa1 = " -enc " ascii 
      $sa2 = " -EncodedCommand " ascii 
      $sa3 = " /enc " ascii 
      $sa4 = " /EncodedCommand " ascii 

      /* Window Hidden */
      $sb1 = " -w hidden " ascii 
      $sb2 = " -window hidden " ascii 
      $sb3 = " -windowstyle hidden " ascii 
      $sb4 = " /w hidden " ascii 
      $sb5 = " /window hidden " ascii 
      $sb6 = " /windowstyle hidden " ascii 

      /* Non Profile */
      $sc1 = " -nop " ascii 
      $sc2 = " -noprofile " ascii 
      $sc3 = " /nop " ascii 
      $sc4 = " /noprofile " ascii 

      /* Non Interactive */
      $sd1 = " -noni " ascii 
      $sd2 = " -noninteractive " ascii 
      $sd3 = " /noni " ascii 
      $sd4 = " /noninteractive " ascii 

      /* Exec Bypass */
      $se1 = " -ep bypass " ascii 
      $se2 = " -exec bypass " ascii 
      $se3 = " -executionpolicy bypass " ascii 
      $se4 = " -exec bypass " ascii 
      $se5 = " /ep bypass " ascii 
      $se6 = " /exec bypass " ascii 
      $se7 = " /executionpolicy bypass " ascii 
      $se8 = " /exec bypass " ascii 

      /* Single Threaded - PowerShell Empire */
      $sf1 = " -sta " ascii 
      $sf2 = " /sta " ascii 

      $fp1 = "Chocolatey Software" ascii 
      $fp2 = "VBOX_MSI_INSTALL_PATH" ascii 
      $fp3 = "\\Local\\Temp\\en-US.ps1" ascii 
      $fp4 = "Lenovo Vantage - Battery Gauge Helper" ascii fullword
      $fp5 = "\\LastPass\\lpwinmetro\\AppxUpgradeUwp.ps1" ascii
      $fp6 = "# use the encoded form to mitigate quoting complications that full scriptblock transfer exposes" ascii /* MS TSSv2 - https://docs.microsoft.com/en-us/troubleshoot/windows-client/windows-troubleshooters/introduction-to-troubleshootingscript-toolset-tssv2 */
      $fp7 = "Write-AnsibleLog \"INFO - s" ascii
      $fp8 = "\\Packages\\Matrix42\\" ascii
      $fp9 = "echo " ascii
      $fp10 = "install" ascii fullword
      $fp11 = "REM " ascii
      $fp12 = "set /p " ascii
      $fp13 = "rxScan Application" ascii 
      $fp14 = "psutil.tests"

      $fpa1 = "All Rights"
      $fpa2 = "<html"
      $fpa2b = "<HTML"
      $fpa3 = "Copyright"
      $fpa4 = "License"
      $fpa5 = "<?xml"
      $fpa6 = "Help" fullword ascii
      $fpa7 = "COPYRIGHT"
condition:
    any of them
}
