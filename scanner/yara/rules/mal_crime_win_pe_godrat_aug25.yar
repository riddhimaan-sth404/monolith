
rule MAL_CRIME_RAT_WIN_PE_GodRat_Aug25 {
   meta:
      description = "Detects GodRAT malware targeting Windows systems"
      author = "Arda Buyukkaya"
      date = "2025-08-23"
      family = "GodRAT"
      reference = "https://securelist.com/godrat/117119/"
      tags = "RAT, Windows, GodRAT, Gh0st RAT, GETGOD"
      victims = "Financial services"
      sha256 = "154e800ed1719dbdcb188c00d5822444717c2a89017f2d12b8511eeeda0c2f41"
      id = "e6ec0af5-71d3-520a-a671-8634ac2f926f"
   strings:
      // WinRT version string
      $winrt_txt = "C++/WinRT version" ascii 

      // API function names blob
      $api_blob = {
         4E 74 43 72 65 61 74 65 53 65 63 74 69 6F 6E 00                          // NtCreateSection
         4E 74 4D 61 70 56 69 65 77 4F 66 53 65 63 74 69 6F 6E 00 00              // NtMapViewOfSection
         4E 74 55 6E 6D 61 70 56 69 65 77 4F 66 53 65 63 74 69 6F 6E 00 00 00 00  // NtUnmapViewOfSection
      }

      // Generic XOR decryption routine pattern using SSE instructions
      // Common characteristics across variants:
      // - Uses SSE instructions (MOVUPS/MOVQ) for efficient XOR operations
      // - Processes ~1900 bytes (0x770/0x76C) of encrypted data
      // - Unrolled loop processing multiple bytes per iteration

      // Load operations - reading XOR key/data into XMM registers
      $ld_movups = { 0F 10 05 ?? ?? ?? ?? }  // movups xmm0, xmmword ptr [address]
      $ld_movq = { F3 0F 7E 05 ?? ?? ?? ?? }  // movq xmm0, qword ptr [address]

      // Store operations - writing XORed data back to memory
      $st_movups = { 0F 11 85 ?? ?? ?? ?? }  // movups xmmword ptr [ebp+offset], xmm0
      $st_movq = { 66 0F D6 85 ?? ?? ?? ?? }  // movq qword ptr [ebp+offset], xmm0

      // String length calculation loop (strlen implementation)
      $scan_loop = { 8A 01 41 84 C0 75 F9 }  // mov al, [ecx]; inc ecx; test al, al; jnz loop

      // Buffer size checks for ~1900 byte decryption
      $cmp_len_770 = { 81 FF 70 07 00 00 0F 82 ?? ?? ?? ?? }  // cmp edi, 0x770 (1904); jb offset
      $cmp_len_76C = { 81 FF 6C 07 00 00 0F 82 ?? ?? ?? ?? }  // cmp edi, 0x76C (1900); jb offset
condition:
    any of them
}
