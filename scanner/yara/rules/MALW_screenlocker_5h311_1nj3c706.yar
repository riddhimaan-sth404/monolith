rule screenlocker_5h311_1nj3c706 {

   meta:

      description = "Rule to detect the screenlocker 5h311_1nj3c706"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2018-08-07"
      rule_version = "v1"
      malware_type = "screenlocker"
      malware_family = "ScreenLocker:W32/5h311_1nj3c706"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://twitter.com/demonslay335/status/1038060120461266944"
      hash = "016ee638bd4fccd5ca438c2e0abddc4b070f59269c08f11c5313ba9c37190718"

   strings:

      $s1 = "C:\\Users\\Hoang Nam\\source\\repos\\WindowsApp22\\WindowsApp22\\obj\\Debug\\WindowsApp22.pdb" fullword ascii
      $s2 = "cmd.exe /cREG add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\ActiveDesktop /v NoChangingWallPaper /t REG_DWOR" ascii 
      $s3 = "C:\\Users\\file1.txt" fullword ascii 
      $s4 = "C:\\Users\\file2.txt" fullword ascii 
      $s5 = "C:\\Users\\file.txt" fullword ascii 
      $s6 = " /v Wallpaper /t REG_SZ /d %temp%\\IMG.jpg /f" fullword ascii 
      $s7 = " /v DisableAntiSpyware /t REG_DWORD /d 1 /f" fullword ascii 
      $s8 = "All your file has been locked. You must pay money to have a key." fullword ascii 
      $s9 = "After we receive Bitcoin from you. We will send key to your email." fullword ascii 
   
condition:
    any of them
}
