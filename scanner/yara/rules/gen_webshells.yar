// only needed for debugging of module math:
//import "console"

/*

Webshell rules by Arnim Rupp (https://github.com/ruppde), Version 2

Rationale behind the rules:
1. a webshell must always execute some kind of payload (in $payload*). the payload is either:
-- direct php function like exec, file write, sql, ...
-- indirect via eval, self defined functions, callbacks, reflection, ...
2. a webshell must always have some way to get the attackers input, e.g. for PHP in $_GET, php://input or $_SERVER (HTTP for headers).

The input may be hidden in obfuscated code, so we look for either:
a) payload + input
b) eval-style-payloads + obfuscation
c) includers (webshell is split in 2+ files)
d) unique strings, if the coder doesn't even intend to hide

Additional conditions will be added to reduce false positves. Check all findings for unintentional webshells aka vulnerabilities ;)

The rules named "suspicious_" are commented by default. uncomment them to find more potentially malicious files at the price of more false positives. if that finds too many results to manually check, you can compare the hashes to virustotal with e.g. https://github.com/Neo23x0/munin

Some samples in the collection were UTF-16 and at least PHP and Java support it, so I use "wide ascii" for all strings. The performance impact is 1%. See also https://thibaud-robin.fr/articles/bypass-filter-upload/

Rules tested on the following webshell repos and collections:
    https://github.com/sensepost/reGeorg
    https://github.com/WhiteWinterWolf/wwwolf-php-webshell
    https://github.com/k8gege/Ladon
    https://github.com/x-o-r-r-o/PHP-Webshells-Collection
    https://github.com/mIcHyAmRaNe/wso-webshell
    https://github.com/LandGrey/webshell-detect-bypass
    https://github.com/threedr3am/JSP-Webshells
    https://github.com/02bx/webshell-venom
    https://github.com/pureqh/webshell
    https://github.com/secwiki/webshell-2
    https://github.com/zhaojh329/rtty
    https://github.com/modux/ShortShells
    https://github.com/epinna/weevely3
    https://github.com/chrisallenlane/novahot
    https://github.com/malwares/WebShell
    https://github.com/tanjiti/webshellSample
    https://github.com/L-codes/Neo-reGeorg
    https://github.com/bayufedra/Tiny-PHP-Webshell
    https://github.com/b374k/b374k
    https://github.com/wireghoul/htshells
    https://github.com/securityriskadvisors/cmd.jsp
    https://github.com/WangYihang/Webshell-Sniper
    https://github.com/Macr0phag3/WebShells
    https://github.com/s0md3v/nano
    https://github.com/JohnTroony/php-webshells
    https://github.com/linuxsec/indoxploit-shell
    https://github.com/hayasec/reGeorg-Weblogic
    https://github.com/nil0x42/phpsploit
    https://github.com/mperlet/pomsky
    https://github.com/FunnyWolf/pystinger
    https://github.com/tanjiti/webshellsample
    https://github.com/lcatro/php-webshell-bypass-waf
    https://github.com/zhzyker/exphub
    https://github.com/dotcppfile/daws
    https://github.com/lcatro/PHP-WebShell-Bypass-WAF
    https://github.com/ysrc/webshell-sample
    https://github.com/JoyChou93/webshell
    https://github.com/k4mpr3t/b4tm4n
    https://github.com/mas1337/webshell
    https://github.com/tengzhangchao/pycmd
    https://github.com/bartblaze/PHP-backdoors
    https://github.com/antonioCoco/SharPyShell
    https://github.com/xl7dev/WebShell
    https://github.com/BlackArch/webshells
    https://github.com/sqlmapproject/sqlmap
    https://github.com/Smaash/quasibot
    https://github.com/tennc/webshell

Webshells in these repos after fdupes run: 4722
Old signature-base rules found: 1315
This rules found: 3286
False positives in 8gb of common webapps plus yara-ci: 2

*/

rule EXT_WEBSHELL_PHP_Generic {
   meta:
      description = "php webshell having some kind of input and some kind of payload. restricted to small files or big ones including suspicious strings"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Arnim Rupp (https://github.com/ruppde)"
      reference = "Internal Research"
      score = 70
      date = "2021-01-14"
      modified = "2026-03-09"
      hash = "bee1b76b1455105d4bfe2f45191071cf05e83a309ae9defcf759248ca9bceddd"
      hash = "6bf351900a408120bee3fc6ea39905c6a35fe6efcf35d0a783ee92062e63a854"
      hash = "e3b4e5ec29628791f836e15500f6fdea19beaf3e8d9981c50714656c50d3b365"
      hash = "00813155bf7f5eb441e1619616a5f6b21ae31afc99caa000c4aafd54b46c3597"
      hash = "e31788042d9cdeffcb279533b5a7359b3beb1144f39bacdd3acdef6e9b4aff25"
      hash = "36b91575a08cf40d4782e5aebcec2894144f1e236a102edda2416bc75cbac8dd"
      hash = "a34154af7c0d7157285cfa498734cfb77662edadb1a10892eb7f7e2fb5e2486c"
      hash = "791a882af2cea0aa8b8379791b401bebc235296858266ddb7f881c8923b7ea61"
      hash = "9a8ab3c225076a26309230d7eac7681f85b271d2db22bf5a190adbf66faca2e6"
      hash = "0d3ee83adc9ebf8fb1a8c449eed5547ee5e67e9a416cce25592e80963198ae23"
      hash = "3d8708609562a27634df5094713154d8ca784dbe89738e63951e12184ff07ad6"
      hash = "70d64d987f0d9ab46514abcc868505d95dbf458387f858b0d7580e4ee8573786"
      hash = "259b3828694b4d256764d7d01b0f0f36ca0526d5ee75e134c6a754d2ab0d1caa"
      hash = "04d139b48d59fa2ef24fb9347b74fa317cb05bd8b7389aeb0a4d458c49ea7540"
      hash = "58d0e2ff61301fe0c176b51430850239d3278c7caf56310d202e0cdbdde9ac3f"
      hash = "731f36a08b0e63c63b3a2a457667dfc34aa7ff3a2aee24e60a8d16b83ad44ce2"
      hash = "e4ffd4ec67762fe00bb8bd9fbff78cffefdb96c16fe7551b5505d319a90fa18f"
      hash = "fa00ee25bfb3908808a7c6e8b2423c681d7c52de2deb30cbaea2ee09a635b7d4"
      hash = "98c1937b9606b1e8e0eebcb116a784c9d2d3db0039b21c45cba399e86c92c2fa"
      hash = "e9423ad8e51895db0e8422750c61ef4897b3be4292b36dba67d42de99e714bff"
      hash = "7a16311a371f03b29d5220484e7ecbe841cfaead4e73c17aa6a9c23b5d94544d"
      hash = "7ca5dec0515dd6f401cb5a52c313f41f5437fc43eb62ea4bcc415a14212d09e9"
      hash = "3de8c04bfdb24185a07f198464fcdd56bb643e1d08199a26acee51435ff0a99f"
      hash = "63297f8c1d4e88415bc094bc5546124c9ed8d57aca3a09e36ae18f5f054ad172"
      hash = "a09dcf52da767815f29f66cb7b03f3d8c102da5cf7b69567928961c389eac11f"
      hash = "d9ae762b011216e520ebe4b7abcac615c61318a8195601526cfa11bbc719a8f1"
      hash = "dd5d8a9b4bb406e0b8f868165a1714fe54ffb18e621582210f96f6e5ae850b33"
      id = "ce3c93a5-3088-5e7e-a0d4-8bea18cf9cc3"
   strings:
      $wfp_tiny1 = "escapeshellarg" fullword ascii
      $wfp_tiny2 = "addslashes" fullword ascii

      //strings from private rule php_false_positive_tiny
      // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
      //$gfp_tiny1 = "addslashes" fullword ascii
      //$gfp_tiny2 = "escapeshellarg" fullword ascii
      $gfp_tiny3 = "include \"./common.php\";"  // xcache
      $gfp_tiny4 = "assert('FALSE');"
      $gfp_tiny5 = "assert(false);"
      $gfp_tiny6 = "assert(FALSE);"
      $gfp_tiny7 = "assert('array_key_exists("
      $gfp_tiny8 = "echo shell_exec($aspellcommand . ' 2>&1');"
      $gfp_tiny9 = "throw new Exception('Could not find authentication source with id ' . $sourceId);"
      $gfp_tiny10 = "return isset( $_POST[ $key ] ) ? $_POST[ $key ] : ( isset( $_REQUEST[ $key ] ) ? $_REQUEST[ $key ] : $default );"
      $gfp_tiny11 = "; This is the recommended, PHP 4-style version of the php.ini-dist file"

      //strings from private rule capa_php_old_safe
      $php_short = "<?" ascii
      // prevent xml and asp from hitting with the short tag
      $no_xml1 = "<?xml version" ascii
      $no_xml2 = "<?xml-stylesheet" ascii
      $no_asp1 = "<%@LANGUAGE" ascii
      $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
      $no_pdf = "<?xpacket"

      // of course the new tags should also match
      // already matched by "<?"
      $php_new1 = /<\?=[^?]/ ascii
      $php_new2 = "<?php" ascii
      $php_new3 = "<script language=\"php" ascii

      //strings from private rule capa_php_input
      $inp1 = "php://input" ascii
      $inp2 = /_GET\s?\[/ ascii
      // for passing $_GET to a function
      $inp3 = /\(\s?\$_GET\s?\)/ ascii
      $inp4 = /_POST\s?\[/ ascii
      $inp5 = /\(\s?\$_POST\s?\)/ ascii
      $inp6 = /_REQUEST\s?\[/ ascii
      $inp7 = /\(\s?\$_REQUEST\s?\)/ ascii
      $inp8 = /\(\s?\$_HEADERS\s?[\)\[]/ ascii
      // PHP automatically adds all the request headers into the $_SERVER global array, prefixing each header name by the "HTTP_" string, so e.g. @eval($_SERVER['HTTP_CMD']) will run any code in the HTTP header CMD
      $inp15 = "_SERVER['HTTP_" ascii
      $inp16 = "_SERVER[\"HTTP_" ascii
      $inp17 = /getenv[\t ]{0,20}\([\t ]{0,20}['"]HTTP_/ ascii
      $inp18 = "array_values($_SERVER)" ascii
      $inp19 = /file_get_contents\("https?:\/\// ascii
      $inp20 = "TSOP_" ascii

      //strings from private rule capa_php_payload
      // \([^)] to avoid matching on e.g. eval() in comments
      $cpayload1 = /\beval[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
      $cpayload2 = /\bexec[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
      $cpayload3 = /\bshell_exec[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
      $cpayload4 = /\bpassthru[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
      $cpayload5 = /\bsystem[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
      $cpayload6 = /\bpopen[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
      $cpayload7 = /\bproc_open[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
      $cpayload8 = /\bpcntl_exec[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
      $cpayload9 = /\bassert[\n\t ]{0,500}\([^)0]/ ascii
      $cpayload10 = /\bpreg_replace[\n\t ]{0,500}\([^\)]{1,100}\/[ismxADSUXju]{0,11}(e|\\x65)/ ascii
      $cpayload12 = /\bmb_ereg_replace[\t ]{0,500}\([^\)]{1,100}'e'/ ascii
      $cpayload13 = /\bmb_eregi_replace[\t ]{0,500}\([^\)]{1,100}'e'/ ascii
      $cpayload20 = /\bcreate_function[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
      $cpayload21 = /\bReflectionFunction[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
      $cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]{0,500}[,}\)]/ ascii

      $m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]{0,500}(\([^\)]|\/\*)/ ascii
      $m_cpayload_preg_filter2 = "'|.{0,500}|e'" ascii
      // TODO backticks

      //strings from private rule capa_gen_sus

      // these strings are just a bit suspicious, so several of them are needed, depending on filesize
      $gen_bit_sus1 = /:\s{0,20}eval}/ ascii
      $gen_bit_sus2 = /\.replace\(\/\w\/g/ ascii
      $gen_bit_sus6 = "self.delete"
      $gen_bit_sus9 = "\"cmd /c"
      $gen_bit_sus10 = "\"cmd\""
      $gen_bit_sus11 = "\"cmd.exe"
      $gen_bit_sus12 = "%comspec%" ascii
      $gen_bit_sus13 = "%COMSPEC%" ascii
      //TODO:$gen_bit_sus12 = ".UserName"
      $gen_bit_sus18 = "Hklm.GetValueNames();" 
      // bonus string for proxylogon exploiting webshells
      $gen_bit_sus19 = "http://schemas.microsoft.com/exchange/" ascii
      $gen_bit_sus21 = "\"upload\"" ascii
      $gen_bit_sus22 = "\"Upload\"" ascii
      $gen_bit_sus23 = "UPLOAD" fullword ascii
      $gen_bit_sus24 = "fileupload" ascii
      $gen_bit_sus25 = "file_upload" ascii
      // own  or base32 func
      $gen_bit_sus29 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" fullword ascii
      $gen_bit_sus29b = "abcdefghijklmnopqrstuvwxyz234567" fullword ascii
      $gen_bit_sus30 = "serv-u" ascii
      $gen_bit_sus31 = "Serv-u" ascii
      $gen_bit_sus32 = "Army" fullword ascii
      // single letter paramweter
      $gen_bit_sus33 = /\$_(GET|POST|REQUEST)\["\w"\]/ fullword ascii
      $gen_bit_sus34 = "Content-Transfer-Encoding: Binary" ascii
      $gen_bit_sus35 = "crack" fullword ascii

      $gen_bit_sus44 = "<pre>" ascii
      $gen_bit_sus45 = "<PRE>" ascii
      $gen_bit_sus46 = "shell_" ascii
      //fp: $gen_bit_sus47 = "Shell" fullword ascii
      $gen_bit_sus50 = "bypass" ascii
      $gen_bit_sus52 = " ^ $" ascii
      $gen_bit_sus53 = ".ssh/authorized_keys" ascii
      $gen_bit_sus55 = /\w'\.'\w/ ascii
      $gen_bit_sus56 = /\w\"\.\"\w/ ascii
      $gen_bit_sus57 = "dumper" ascii
      $gen_bit_sus59 = "'cmd'" ascii
      $gen_bit_sus60 = "\"execute\"" ascii
      $gen_bit_sus61 = "/bin/sh" ascii
      $gen_bit_sus62 = "Cyber" ascii
      $gen_bit_sus63 = "portscan" fullword ascii
      //$gen_bit_sus64 = "\"command\"" fullword ascii
      //$gen_bit_sus65 = "'command'" fullword ascii
      $gen_bit_sus66 = "whoami" fullword ascii
      $gen_bit_sus67 = "$password='" fullword ascii
      $gen_bit_sus68 = "$password=\"" fullword ascii
      $gen_bit_sus69 = "$cmd" fullword ascii
      $gen_bit_sus70 = "\"?>\"." fullword ascii
      $gen_bit_sus71 = "Hacking" fullword ascii
      $gen_bit_sus72 = "hacking" fullword ascii
      $gen_bit_sus73 = ".htpasswd" ascii
      $gen_bit_sus74 = /\btouch\(\$[^,]{1,30},/ ascii
      $gen_bit_sus75 = "uploaded" fullword ascii

      // very suspicious strings, one is enough
      $gen_much_sus7 = "Web Shell" 
      $gen_much_sus8 = "WebShell" 
      $gen_much_sus3 = "hidded shell"
      $gen_much_sus4 = "WScript.Shell.1" 
      $gen_much_sus5 = "AspExec"
      $gen_much_sus14 = "\\pcAnywhere\\" 
      $gen_much_sus15 = "antivirus" 
      $gen_much_sus16 = "McAfee" 
      $gen_much_sus17 = "nishang"
      $gen_much_sus18 = "\"unsafe" fullword ascii
      $gen_much_sus19 = "'unsafe" fullword ascii
      $gen_much_sus24 = "exploit" fullword ascii
      $gen_much_sus25 = "Exploit" fullword ascii
      $gen_much_sus26 = "TVqQAAMAAA" ascii
      $gen_much_sus30 = "Hacker" ascii
      $gen_much_sus31 = "HACKED" fullword ascii
      $gen_much_sus32 = "hacked" fullword ascii
      $gen_much_sus33 = "hacker" ascii
      $gen_much_sus34 = "grayhat" ascii
      $gen_much_sus35 = "Microsoft FrontPage" ascii
      $gen_much_sus36 = "Rootkit" ascii
      $gen_much_sus37 = "rootkit" ascii
      $gen_much_sus38 = "/*-/*-*/" ascii
      $gen_much_sus39 = "u\"+\"n\"+\"s" ascii
      $gen_much_sus40 = "\"e\"+\"v" ascii
      $gen_much_sus41 = "a\"+\"l\"" ascii
      $gen_much_sus42 = "\"+\"(\"+\"" ascii
      $gen_much_sus43 = "q\"+\"u\"" ascii
      $gen_much_sus44 = "\"u\"+\"e" ascii
      $gen_much_sus45 = "/*//*/" ascii
      $gen_much_sus46 = "(\"/*/\"" ascii
      $gen_much_sus47 = "eval(eval(" ascii
      // self remove
      $gen_much_sus48 = "unlink(__FILE__)" ascii
      $gen_much_sus49 = "Shell.Users" ascii
      $gen_much_sus50 = "PasswordType=Regular" ascii
      $gen_much_sus51 = "-Expire=0" ascii
      $gen_much_sus60 = "_=$$_" ascii
      $gen_much_sus62 = "++;$" ascii
      $gen_much_sus63 = "++; $" ascii
      $gen_much_sus64 = "_.=$_" ascii
      $gen_much_sus70 = "-perm -04000" ascii
      $gen_much_sus71 = "-perm -02000" ascii
      $gen_much_sus72 = "grep -li password" ascii
      $gen_much_sus73 = "-name config.inc.php" ascii
      // touch without parameters sets the time to now, not malicious and gives fp
      $gen_much_sus75 = "password crack" ascii
      $gen_much_sus76 = "mysqlDll.dll" ascii
      $gen_much_sus77 = "net user" ascii
      $gen_much_sus80 = "fopen(\".htaccess\",\"w" ascii
      $gen_much_sus81 = /strrev\(['"]/ ascii
      $gen_much_sus82 = "PHPShell" fullword ascii
      $gen_much_sus821 = "PHP Shell" fullword ascii
      $gen_much_sus83 = "phpshell" fullword ascii
      $gen_much_sus84 = "PHPshell" fullword ascii
      $gen_much_sus87 = "deface" ascii
      $gen_much_sus88 = "Deface" ascii
      $gen_much_sus89 = "backdoor" ascii
      $gen_much_sus90 = "r00t" fullword ascii
      $gen_much_sus91 = "xp_cmdshell" fullword ascii
      $gen_much_sus92 = "str_rot13" fullword ascii

      //strings from private rule capa_php_payload_multiple
      // \([^)] to avoid matching on e.g. eval() in comments
      $cmpayload1 = /\beval[\t ]{0,500}\([^)]/ ascii
      $cmpayload2 = /\bexec[\t ]{0,500}\([^)]/ ascii
      $cmpayload3 = /\bshell_exec[\t ]{0,500}\([^)]/ ascii
      $cmpayload4 = /\bpassthru[\t ]{0,500}\([^)]/ ascii
      $cmpayload5 = /\bsystem[\t ]{0,500}\([^)]/ ascii
      $cmpayload6 = /\bpopen[\t ]{0,500}\([^)]/ ascii
      $cmpayload7 = /\bproc_open[\t ]{0,500}\([^)]/ ascii
      $cmpayload8 = /\bpcntl_exec[\t ]{0,500}\([^)]/ ascii
      $cmpayload9 = /\bassert[\t ]{0,500}\([^)0]/ ascii
      $cmpayload10 = /\bpreg_replace[\t ]{0,500}\([^\)]{1,100}\/e/ ascii
      $cmpayload11 = /\bpreg_filter[\t ]{0,500}\([^\)]{1,100}\/e/ ascii
      $cmpayload12 = /\bmb_ereg_replace[\t ]{0,500}\([^\)]{1,100}'e'/ ascii
      $cmpayload20 = /\bcreate_function[\t ]{0,500}\([^)]/ ascii
      $cmpayload21 = /\bReflectionFunction[\t ]{0,500}\([^)]/ ascii

      $fp1 = "# Some examples from obfuscated malware:" ascii
      $fp2 = "{@see TFileUpload} for further details." ascii
condition:
    any of them
}


rule WEBSHELL_PHP_Generic_Callback
{
    meta:
        description = "php webshell having some kind of input and using a callback to execute the payload. restricted to small files or would give lots of false positives"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/01/14"
        modified = "2023-09-18"
        score = 60
        hash = "e98889690101b59260e871c49263314526f2093f"
        hash = "63297f8c1d4e88415bc094bc5546124c9ed8d57aca3a09e36ae18f5f054ad172"
        hash = "81388c8cc99353cdb42572bb88df7d3bd70eefc748c2fa4224b6074aa8d7e6a2"
        hash = "27d3bfabc283d851b0785199da8b1b0384afcb996fa9217687274dd56a7b5f49"
        hash = "ee256d7cc3ceb2bf3a1934d553cdd36e3fbde62a02b20a1b748a74e85d4dbd33"
        hash = "4adc6c5373c4db7b8ed1e7e6df10a3b2ce5e128818bb4162d502056677c6f54a"
        hash = "1fe4c60ea3f32819a98b1725581ac912d0f90d497e63ad81ccf258aeec59fee3"
        hash = "2967f38c26b131f00276bcc21227e54ee6a71881da1d27ec5157d83c4c9d4f51"
        hash = "1ba02fb573a06d5274e30b2b05573305294497769414e964a097acb5c352fb92"
        hash = "f4fe8e3b2c39090ca971a8e61194fdb83d76fadbbace4c5eb15e333df61ce2a4"
        hash = "badda1053e169fea055f5edceae962e500842ad15a5d31968a0a89cf28d89e91"
        hash = "0a29cf1716e67a7932e604c5d3df4b7f372561200c007f00131eef36f9a4a6a2"
        hash = "51c2c8b94c4b8cce806735bcf6e5aa3f168f0f7addce47b699b9a4e31dc71b47"
        hash = "de1ef827bcd3100a259f29730cb06f7878220a7c02cee0ebfc9090753d2237a8"
        hash = "487e8c08e85774dfd1f5e744050c08eb7d01c6877f7d03d7963187748339e8c4"

        id = "e33dba84-bbeb-5955-a81b-2d2c8637fb48"
    strings:

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"

        //strings from private rule php_false_positive_tiny
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        //$gfp_tiny1 = "addslashes" fullword ascii
        //$gfp_tiny2 = "escapeshellarg" fullword ascii
        $gfp_tiny3 = "include \"./common.php\";" // xcache
        $gfp_tiny4 = "assert('FALSE');"
        $gfp_tiny5 = "assert(false);"
        $gfp_tiny6 = "assert(FALSE);"
        $gfp_tiny7 = "assert('array_key_exists("
        $gfp_tiny8 = "echo shell_exec($aspellcommand . ' 2>&1');"
        $gfp_tiny9 = "throw new Exception('Could not find authentication source with id ' . $sourceId);"
        $gfp_tiny10= "return isset( $_POST[ $key ] ) ? $_POST[ $key ] : ( isset( $_REQUEST[ $key ] ) ? $_REQUEST[ $key ] : $default );"

        //strings from private rule capa_php_input
        $inp1 = "php://input" ascii
        $inp2 = /_GET\s?\[/ ascii
        // for passing $_GET to a function
        $inp3 = /\(\s?\$_GET\s?\)/ ascii
        $inp4 = /_POST\s?\[/ ascii
        $inp5 = /\(\s?\$_POST\s?\)/ ascii
        $inp6 = /_REQUEST\s?\[/ ascii
        $inp7 = /\(\s?\$_REQUEST\s?\)/ ascii
        // PHP automatically adds all the request headers into the $_SERVER global array, prefixing each header name by the "HTTP_" string, so e.g. @eval($_SERVER['HTTP_CMD']) will run any code in the HTTP header CMD
        $inp15 = "_SERVER['HTTP_" ascii
        $inp16 = "_SERVER[\"HTTP_" ascii
        $inp17 = /getenv[\t ]{0,20}\([\t ]{0,20}['"]HTTP_/ ascii
        $inp18 = "array_values($_SERVER)" ascii
        $inp19 = /file_get_contents\("https?:\/\// ascii

        // TODO: arraywalk \n /*
        //strings from private rule capa_php_callback
        // the end is 1. ( followed by anything but a direct closing ) 2. /* for the start of an obfuscation comment
        $callback1 = /\bob_start[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback2 = /\barray_diff_uassoc[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback3 = /\barray_diff_ukey[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback4 = /\barray_filter[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback5 = /\barray_intersect_uassoc[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback6 = /\barray_intersect_ukey[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback7 = /\barray_map[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback8 = /\barray_reduce[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback9 = /\barray_udiff_assoc[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback10 = /\barray_udiff_uassoc[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback11 = /\barray_udiff[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback12 = /\barray_uintersect_assoc[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback13 = /\barray_uintersect_uassoc[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback14 = /\barray_uintersect[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback15 = /\barray_walk_recursive[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback16 = /\barray_walk[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback17 = /\bassert_options[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback18 = /\buasort[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback19 = /\buksort[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback20 = /\busort[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback21 = /\bpreg_replace_callback[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback22 = /\bspl_autoload_register[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback23 = /\biterator_apply[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback24 = /\bcall_user_func[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback25 = /\bcall_user_func_array[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback26 = /\bregister_shutdown_function[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback27 = /\bregister_tick_function[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback28 = /\bset_error_handler[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback29 = /\bset_exception_handler[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback30 = /\bsession_set_save_handler[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback31 = /\bsqlite_create_aggregate[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback32 = /\bsqlite_create_function[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback33 = /\bmb_ereg_replace_callback[\n\t ]{0,500}(\([^)]|\/\*)/ ascii

        $m_callback1 = /\bfilter_var[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $m_callback2 = "FILTER_CALLBACK" fullword ascii

        $cfp1 = /ob_start\(['\"]ob_gzhandler/ ascii
        $cfp2 = "IWPML_Backend_Action_Loader" ascii 
        $cfp3 = "<?phpclass WPML" ascii

        //strings from private rule capa_gen_sus

        // these strings are just a bit suspicious, so several of them are needed, depending on filesize
        $gen_bit_sus1  = /:\s{0,20}eval}/ ascii
        $gen_bit_sus2  = /\.replace\(\/\w\/g/ ascii
        $gen_bit_sus6  = "self.delete"
        $gen_bit_sus9  = "\"cmd /c"
        $gen_bit_sus10 = "\"cmd\""
        $gen_bit_sus11 = "\"cmd.exe"
        $gen_bit_sus12 = "%comspec%" ascii
        $gen_bit_sus13 = "%COMSPEC%" ascii
        //TODO:$gen_bit_sus12 = ".UserName"
        $gen_bit_sus18 = "Hklm.GetValueNames();" 
        // bonus string for proxylogon exploiting webshells
        $gen_bit_sus19 = "http://schemas.microsoft.com/exchange/" ascii
        $gen_bit_sus21 = "\"upload\"" ascii
        $gen_bit_sus22 = "\"Upload\"" ascii
        $gen_bit_sus23 = "UPLOAD" fullword ascii
        $gen_bit_sus24 = "fileupload" ascii
        $gen_bit_sus25 = "file_upload" ascii
        // own  or base32 func
        $gen_bit_sus29 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" fullword ascii
        $gen_bit_sus29b = "abcdefghijklmnopqrstuvwxyz234567" fullword ascii
        $gen_bit_sus30 = "serv-u" ascii
        $gen_bit_sus31 = "Serv-u" ascii
        $gen_bit_sus32 = "Army" fullword ascii
        // single letter paramweter
        $gen_bit_sus33 = /\$_(GET|POST|REQUEST)\["\w"\]/ fullword ascii
        $gen_bit_sus34 = "Content-Transfer-Encoding: Binary" ascii
        $gen_bit_sus35 = "crack" fullword ascii

        $gen_bit_sus44 = "<pre>" ascii
        $gen_bit_sus45 = "<PRE>" ascii
        $gen_bit_sus46 = "shell_" ascii
        //fp: $gen_bit_sus47 = "Shell" fullword ascii
        $gen_bit_sus50 = "bypass" ascii
        $gen_bit_sus52 = " ^ $" ascii
        $gen_bit_sus53 = ".ssh/authorized_keys" ascii
        $gen_bit_sus55 = /\w'\.'\w/ ascii
        $gen_bit_sus56 = /\w\"\.\"\w/ ascii
        $gen_bit_sus57 = "dumper" ascii
        $gen_bit_sus59 = "'cmd'" ascii
        $gen_bit_sus60 = "\"execute\"" ascii
        $gen_bit_sus61 = "/bin/sh" ascii
        $gen_bit_sus62 = "Cyber" ascii
        $gen_bit_sus63 = "portscan" fullword ascii
        //$gen_bit_sus64 = "\"command\"" fullword ascii
        //$gen_bit_sus65 = "'command'" fullword ascii
        $gen_bit_sus66 = "whoami" fullword ascii
        $gen_bit_sus67 = "$password='" fullword ascii
        $gen_bit_sus68 = "$password=\"" fullword ascii
        $gen_bit_sus69 = "$cmd" fullword ascii
        $gen_bit_sus70 = "\"?>\"." fullword ascii
        $gen_bit_sus71 = "Hacking" fullword ascii
        $gen_bit_sus72 = "hacking" fullword ascii
        $gen_bit_sus73 = ".htpasswd" ascii
        $gen_bit_sus74 = /\btouch\(\$[^,]{1,30},/ ascii

        // very suspicious strings, one is enough
        $gen_much_sus7  = "Web Shell" 
        $gen_much_sus8  = "WebShell" 
        $gen_much_sus3  = "hidded shell"
        $gen_much_sus4  = "WScript.Shell.1" 
        $gen_much_sus5  = "AspExec"
        $gen_much_sus14 = "\\pcAnywhere\\" 
        $gen_much_sus15 = "antivirus" 
        $gen_much_sus16 = "McAfee" 
        $gen_much_sus17 = "nishang"
        $gen_much_sus18 = "\"unsafe" fullword ascii
        $gen_much_sus19 = "'unsafe" fullword ascii
        $gen_much_sus24 = "exploit" fullword ascii
        $gen_much_sus25 = "Exploit" fullword ascii
        $gen_much_sus26 = "TVqQAAMAAA" ascii
        $gen_much_sus30 = "Hacker" ascii
        $gen_much_sus31 = "HACKED" fullword ascii
        $gen_much_sus32 = "hacked" fullword ascii
        $gen_much_sus33 = "hacker" ascii
        $gen_much_sus34 = "grayhat" ascii
        $gen_much_sus35 = "Microsoft FrontPage" ascii
        $gen_much_sus36 = "Rootkit" ascii
        $gen_much_sus37 = "rootkit" ascii
        $gen_much_sus38 = "/*-/*-*/" ascii
        $gen_much_sus39 = "u\"+\"n\"+\"s" ascii
        $gen_much_sus40 = "\"e\"+\"v" ascii
        $gen_much_sus41 = "a\"+\"l\"" ascii
        $gen_much_sus42 = "\"+\"(\"+\"" ascii
        $gen_much_sus43 = "q\"+\"u\"" ascii
        $gen_much_sus44 = "\"u\"+\"e" ascii
        $gen_much_sus45 = "/*//*/" ascii
        $gen_much_sus46 = "(\"/*/\"" ascii
        $gen_much_sus47 = "eval(eval(" ascii
        // self remove
        $gen_much_sus48 = "unlink(__FILE__)" ascii
        $gen_much_sus49 = "Shell.Users" ascii
        $gen_much_sus50 = "PasswordType=Regular" ascii
        $gen_much_sus51 = "-Expire=0" ascii
        $gen_much_sus60 = "_=$$_" ascii
        $gen_much_sus61 = "_=$$_" ascii
        $gen_much_sus62 = "++;$" ascii
        $gen_much_sus63 = "++; $" ascii
        $gen_much_sus64 = "_.=$_" ascii
        $gen_much_sus70 = "-perm -04000" ascii
        $gen_much_sus71 = "-perm -02000" ascii
        $gen_much_sus72 = "grep -li password" ascii
        $gen_much_sus73 = "-name config.inc.php" ascii
        // touch without parameters sets the time to now, not malicious and gives fp
        $gen_much_sus75 = "password crack" ascii
        $gen_much_sus76 = "mysqlDll.dll" ascii
        $gen_much_sus77 = "net user" ascii
        $gen_much_sus80 = "fopen(\".htaccess\",\"w" ascii
        $gen_much_sus81 = /strrev\(['"]/ ascii
        $gen_much_sus82 = "PHPShell" fullword ascii
        $gen_much_sus821= "PHP Shell" fullword ascii
        $gen_much_sus83 = "phpshell" fullword ascii
        $gen_much_sus84 = "PHPshell" fullword ascii
        $gen_much_sus87 = "deface" ascii
        $gen_much_sus88 = "Deface" ascii
        $gen_much_sus89 = "backdoor" ascii
        $gen_much_sus90 = "r00t" fullword ascii
        $gen_much_sus91 = "xp_cmdshell" fullword ascii
        $gen_much_sus92 = "base64_decode(base64_decode(" fullword ascii
        $gen_much_sus93 = "eval(\"/*" ascii
        $gen_much_sus94 = "http_response_code(404)" ascii

        $gif = { 47 49 46 38 }


condition:
    any of them
}

rule WEBSHELL_PHP_Base64_Encoded_Payloads {
    meta:
        description = "php webshell containing  encoded payload"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "88d0d4696c9cb2d37d16e330e236cb37cfaec4cd"
        hash = "e3b4e5ec29628791f836e15500f6fdea19beaf3e8d9981c50714656c50d3b365"
        hash = "e726cd071915534761822805724c6c6bfe0fcac604a86f09437f03f301512dc5"
        hash = "39b8871928d00c7de8d950d25bff4cb19bf9bd35942f7fee6e0f397ff42fbaee"
        hash = "8cc9802769ede56f1139abeaa0735526f781dff3b6c6334795d1d0f19161d076"
        hash = "4cda0c798908b61ae7f4146c6218d7b7de14cbcd7c839edbdeb547b5ae404cd4"
        hash = "afd9c9b0df0b2ca119914ea0008fad94de3bd93c6919f226b793464d4441bdf4"
        hash = "b2048dc30fc7681094a0306a81f4a4cc34f0b35ccce1258c20f4940300397819"
        hash = "da6af9a4a60e3a484764010fbf1a547c2c0a2791e03fc11618b8fc2605dceb04"
        hash = "222cd9b208bd24955bcf4f9976f9c14c1d25e29d361d9dcd603d57f1ea2b0aee"
        hash = "98c1937b9606b1e8e0eebcb116a784c9d2d3db0039b21c45cba399e86c92c2fa"
        hash = "6b6cd1ef7e78e37cbcca94bfb5f49f763ba2f63ed8b33bc4d7f9e5314c87f646"
        hash = "51c2c8b94c4b8cce806735bcf6e5aa3f168f0f7addce47b699b9a4e31dc71b47"
        hash = "7a16311a371f03b29d5220484e7ecbe841cfaead4e73c17aa6a9c23b5d94544d"
        hash = "e2b1dfcfaa61e92526a3a444be6c65330a8db4e692543a421e19711760f6ffe2"

        id = "4e42b47d-725b-5e1f-9408-6c6329f60506"
    strings:
        $decode1 = "base64_decode" fullword ascii
        $decode2 = "openssl_decrypt" fullword ascii
        // exec
        $one1 = "leGVj"
        $one2 = "V4ZW"
        $one3 = "ZXhlY"
        $one4 = "UAeABlAGMA"
        $one5 = "lAHgAZQBjA"
        $one6 = "ZQB4AGUAYw"
        // shell_exec
        $two1 = "zaGVsbF9leGVj"
        $two2 = "NoZWxsX2V4ZW"
        $two3 = "c2hlbGxfZXhlY"
        $two4 = "MAaABlAGwAbABfAGUAeABlAGMA"
        $two5 = "zAGgAZQBsAGwAXwBlAHgAZQBjA"
        $two6 = "cwBoAGUAbABsAF8AZQB4AGUAYw"
        // passthru
        $three1 = "wYXNzdGhyd"
        $three2 = "Bhc3N0aHJ1"
        $three3 = "cGFzc3Rocn"
        $three4 = "AAYQBzAHMAdABoAHIAdQ"
        $three5 = "wAGEAcwBzAHQAaAByAHUA"
        $three6 = "cABhAHMAcwB0AGgAcgB1A"
        // system
        $four1 = "zeXN0ZW"
        $four2 = "N5c3Rlb"
        $four3 = "c3lzdGVt"
        $four4 = "MAeQBzAHQAZQBtA"
        $four5 = "zAHkAcwB0AGUAbQ"
        $four6 = "cwB5AHMAdABlAG0A"
        // popen
        $five1 = "wb3Blb"
        $five2 = "BvcGVu"
        $five3 = "cG9wZW"
        $five4 = "AAbwBwAGUAbg"
        $five5 = "wAG8AcABlAG4A"
        $five6 = "cABvAHAAZQBuA"
        // proc_open
        $six1 = "wcm9jX29wZW"
        $six2 = "Byb2Nfb3Blb"
        $six3 = "cHJvY19vcGVu"
        $six4 = "AAcgBvAGMAXwBvAHAAZQBuA"
        $six5 = "wAHIAbwBjAF8AbwBwAGUAbg"
        $six6 = "cAByAG8AYwBfAG8AcABlAG4A"
        // pcntl_exec
        $seven1 = "wY250bF9leGVj"
        $seven2 = "BjbnRsX2V4ZW"
        $seven3 = "cGNudGxfZXhlY"
        $seven4 = "AAYwBuAHQAbABfAGUAeABlAGMA"
        $seven5 = "wAGMAbgB0AGwAXwBlAHgAZQBjA"
        $seven6 = "cABjAG4AdABsAF8AZQB4AGUAYw"
        // eval
        $eight1 = "ldmFs"
        $eight2 = "V2YW"
        $eight3 = "ZXZhb"
        $eight4 = "UAdgBhAGwA"
        $eight5 = "lAHYAYQBsA"
        $eight6 = "ZQB2AGEAbA"
        // assert
        $nine1 = "hc3Nlcn"
        $nine2 = "Fzc2Vyd"
        $nine3 = "YXNzZXJ0"
        $nine4 = "EAcwBzAGUAcgB0A"
        $nine5 = "hAHMAcwBlAHIAdA"
        $nine6 = "YQBzAHMAZQByAHQA"

        // false positives

        // execu
        $execu1 = "leGVjd"
        $execu2 = "V4ZWN1"
        $execu3 = "ZXhlY3"

        // esystem like e.g. filesystem
        $esystem1 = "lc3lzdGVt"
        $esystem2 = "VzeXN0ZW"
        $esystem3 = "ZXN5c3Rlb"

        // opening
        $opening1 = "vcGVuaW5n"
        $opening2 = "9wZW5pbm"
        $opening3 = "b3BlbmluZ"

        // false positives
        $fp1 = { D0 CF 11 E0 A1 B1 1A E1 }
        // api.telegram
        $fp2 = "YXBpLnRlbGVncmFtLm9"
        // Log files
        $fp3 = " GET /"
        $fp4 = " POST /"

    $fpa1 = "/cn=Recipients"

        //strings from private rule capa_php_old_safe
        $php_short = "<?" ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" ascii
        $no_xml2 = "<?xml-stylesheet" ascii
        $no_asp1 = "<%@LANGUAGE" ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ ascii
        $php_new2 = "<?php" ascii
        $php_new3 = "<script language=\"php" ascii

condition:
    any of them
}

rule WEBSHELL_PHP_Unknown_1
{
    meta:
        description = "obfuscated php webshell"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        hash = "12ce6c7167b33cc4e8bdec29fb1cfc44ac9487d1"
        hash = "cf4abbd568ce0c0dfce1f2e4af669ad2"
        date = "2021/01/07"
        modified = "2023-04-05"

        id = "93d01a4c-4c18-55d2-b682-68a1f6460889"
    strings:
        $sp0 = /^<\?php \$[a-z]{3,30} = '/ wide ascii
        $sp1 = "=explode(chr(" ascii
        $sp2 = "; if (!function_exists('" ascii
        $sp3 = " = NULL; for(" ascii

condition:
    any of them
}

rule WEBSHELL_PHP_Generic_Eval
{
    meta:
        description = "Generic PHP webshell which uses any eval/exec function in the same line with user input"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "a61437a427062756e2221bfb6d58cd62439d09d9"
        hash = "90c5cc724ec9cf838e4229e5e08955eec4d7bf95"
        hash = "2b41abc43c5b6c791d4031005bf7c5104a98e98a00ee24620ce3e8e09a78e78f"
        hash = "5c68a0fa132216213b66a114375b07b08dc0cb729ddcf0a29bff9ca7a22eaaf4"
        hash = "de3c01f55d5346577922bbf449faaaaa1c8d1aaa64c01e8a1ee8c9d99a41a1be"
        hash = "124065176d262bde397b1911648cea16a8ff6a4c8ab072168d12bf0662590543"
        hash = "cd7450f3e5103e68741fd086df221982454fbcb067e93b9cbd8572aead8f319b"
        hash = "ab835ce740890473adf5cc804055973b926633e39c59c2bd98da526b63e9c521"
        hash = "31ff9920d401d4fbd5656a4f06c52f1f54258bc42332fc9456265dca7bb4c1ea"
        hash = "64e6c08aa0b542481b86a91cdf1f50c9e88104a8a4572a8c6bd312a9daeba60e"
        hash = "80e98e8a3461d7ba15d869b0641cdd21dd5b957a2006c3caeaf6f70a749ca4bb"
        hash = "93982b8df76080e7ba4520ae4b4db7f3c867f005b3c2f84cb9dff0386e361c35"
        hash = "51c2c8b94c4b8cce806735bcf6e5aa3f168f0f7addce47b699b9a4e31dc71b47"
        hash = "7a16311a371f03b29d5220484e7ecbe841cfaead4e73c17aa6a9c23b5d94544d"
        hash = "7ca5dec0515dd6f401cb5a52c313f41f5437fc43eb62ea4bcc415a14212d09e9"
        hash = "fd5f0f81204ca6ca6e93343500400d5853012e88254874fc9f62efe0fde7ab3c"
        hash = "883f48ed4e9646da078cabf6b8b4946d9f199660262502650f76450ecf60ddd5"
        hash = "6d042b6393669bb4d98213091cabe554ab192a6c916e86c04d06cc2a4ca92c00"
        hash = "dd5d8a9b4bb406e0b8f868165a1714fe54ffb18e621582210f96f6e5ae850b33"


        id = "79cfbd88-f6f7-5cba-a325-0a99962139ca"
    strings:
        // new: eval($GLOBALS['_POST'
        $geval = /\b(exec|shell_exec|passthru|system|popen|proc_open|pcntl_exec|eval|assert)[\t ]{0,300}(\(base64_decode)?(\(stripslashes)?[\t ]{0,300}(\(trim)?[\t ]{0,300}\(\$(_POST|_GET|_REQUEST|_SERVER\s?\[['"]HTTP_|GLOBALS\[['"]_(POST|GET|REQUEST))/ ascii

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"
        // Log files
        $gfp_3 = " GET /"
        $gfp_4 = " POST /"
condition:
    any of them
}

rule WEBSHELL_PHP_Double_Eval_Tiny
{
    meta:
        description = "PHP webshell which probably hides the input inside an eval()ed obfuscated string"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 70
        date = "2021-01-11"
        modified = "2026-02-23"
        hash = "f66fb918751acc7b88a17272a044b5242797976c73a6e54ac6b04b02f61e9761"
        hash = "6b2f0a3bd80019dea536ddbf92df36ab897dd295840cb15bb7b159d0ee2106ff"
        hash = "aabfd179aaf716929c8b820eefa3c1f613f8dcac"
        hash = "9780c70bd1c76425d4313ca7a9b89dda77d2c664"
        hash = "006620d2a701de73d995fc950691665c0692af11"


        id = "868db363-83d3-57e2-ac8d-c6125e9bdd64"
    strings:
        $payload = /(\beval[\t ]{0,500}\([^)]|\bassert[\t ]{0,500}\([^)])/ ascii
        $fp1 = "clone" fullword ascii
        $fp2 = "* @assert" ascii
        $fp3 = "*@assert" ascii
        $fp4 = "--EXPECT--" ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" ascii
        $no_xml2 = "<?xml-stylesheet" ascii
        $no_asp1 = "<%@LANGUAGE" ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ ascii
        $php_new2 = "<?php" ascii
        $php_new3 = "<script language=\"php" ascii

condition:
    any of them
}

rule WEBSHELL_PHP_OBFUSC
{
    meta:
        description = "PHP webshell obfuscated"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/12"
        modified = "2025-09-22"
        hash = "eec9ac58a1e763f5ea0f7fa249f1fe752047fa60"
        hash = "181a71c99a4ae13ebd5c94bfc41f9ec534acf61cd33ef5bce5fb2a6f48b65bf4"
        hash = "76d4e67e13c21662c4b30aab701ce9cdecc8698696979e504c288f20de92aee7"
        hash = "1d0643927f04cb1133f00aa6c5fa84aaf88e5cf14d7df8291615b402e8ab6dc2"
        id = "f66e337b-8478-5cd3-b01a-81133edaa8e5"
    strings:

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"
        $gfp13 = "assert(\\\""
        $gfp14 = "PhutilUTF8TestCase"
        $gfp15 = "chr(195).chr(128) => 'A'," // 3d413ceb54e929d6af2e64ebb8df7ba2452a7aac876dddcf6336c3445e7bcc91, wordpress formatter.php

        //strings from private rule capa_php_old_safe
        $php_short = "<?" ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" ascii
        $no_xml2 = "<?xml-stylesheet" ascii
        $no_asp1 = "<%@LANGUAGE" ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ ascii
        $php_new2 = "<?php" ascii
        $php_new3 = "<script language=\"php" ascii

        //strings from private rule capa_php_obfuscation_multi
        $o1 = "chr(" ascii
        $o2 = "chr (" ascii
        // not excactly a string function but also often used in obfuscation
        $o3 = "goto" fullword ascii
        $o4 = "\\x9" ascii
        $o5 = "\\x3" ascii
        // just picking some random numbers because they should appear often enough in a long obfuscated blob and it's faster than a regex
        $o6 = "\\61" ascii
        $o7 = "\\44" ascii
        $o8 = "\\112" ascii
        $o9 = "\\120" ascii
        $fp1 = "$goto" ascii

        //strings from private rule capa_php_payload
        // \([^)] to avoid matching on e.g. eval() in comments
        $cpayload1 = /\beval[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload2 = /\bexec[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload3 = /\bshell_exec[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload4 = /\bpassthru[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload5 = /\bsystem[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload6 = /\bpopen[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload7 = /\bproc_open[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload8 = /\bpcntl_exec[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload9 = /\bassert[\n\t ]{0,500}\([^)0]/ ascii
        $cpayload10 = /\bpreg_replace[\n\t ]{0,500}\([^\)]{1,100}\/[ismxADSUXju]{0,11}(e|\\x65)/ ascii
        $cpayload12 = /\bmb_ereg_replace[\t ]{0,500}\([^\)]{1,100}'e'/ ascii
        $cpayload13 = /\bmb_eregi_replace[\t ]{0,500}\([^\)]{1,100}'e'/ ascii
        $cpayload20 = /\bcreate_function[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload21 = /\bReflectionFunction[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]{0,500}[,}\)]/ ascii

        $m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]{0,500}(\([^\)]|\/\*)/ ascii
        $m_cpayload_preg_filter2 = "'|.*|e'" ascii
        // TODO backticks

condition:
    any of them
}

rule WEBSHELL_PHP_OBFUSC_Encoded
{
    meta:
        description = "PHP webshell obfuscated by encoding"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/04/18"
        modified = "2023-04-05"
        score = 70
        hash = "119fc058c9c5285498a47aa271ac9a27f6ada1bf4d854ccd4b01db993d61fc52"
        hash = "d5ca3e4505ea122019ea263d6433221030b3f64460d3ce2c7d0d63ed91162175"
        hash = "8a1e2d72c82f6a846ec066d249bfa0aaf392c65149d39b7b15ba19f9adc3b339"


        id = "134c1189-1b41-58d5-af66-beaa4795a704"
    strings:
        // one without plain e, one without plain v, to avoid hitting on plain "eval("
        $enc_eval1 = /(e|\\x65|\\101)(\\x76|\\118)(a|\\x61|\\97)(l|\\x6c|\\108)(\(|\\x28|\\40)/ ascii
        $enc_eval2 = /(\\x65|\\101)(v|\\x76|\\118)(a|\\x61|\\97)(l|\\x6c|\\108)(\(|\\x28|\\40)/ ascii
        // one without plain a, one without plain s, to avoid hitting on plain "assert("
        $enc_assert1 = /(a|\\97|\\x61)(\\115|\\x73)(s|\\115|\\x73)(e|\\101|\\x65)(r|\\114|\\x72)(t|\\116|\\x74)(\(|\\x28|\\40)/ ascii
        $enc_assert2 = /(\\97|\\x61)(s|\\115|\\x73)(s|\\115|\\x73)(e|\\101|\\x65)(r|\\114|\\x72)(t|\\116|\\x74)(\(|\\x28|\\40)/ ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" ascii
        $no_xml2 = "<?xml-stylesheet" ascii
        $no_asp1 = "<%@LANGUAGE" ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ ascii
        $php_new2 = "<?php" ascii
        $php_new3 = "<script language=\"php" ascii

condition:
    any of them
}

rule WEBSHELL_PHP_OBFUSC_Encoded_Mixed_Dec_And_Hex
{
    meta:
        description = "PHP webshell obfuscated by encoding of mixed hex and dec"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/04/18"
        modified = "2023-04-05"
        hash = "0e21931b16f30b1db90a27eafabccc91abd757fa63594ba8a6ad3f477de1ab1c"
        hash = "929975272f0f42bf76469ed89ebf37efcbd91c6f8dac1129c7ab061e2564dd06"
        hash = "88fce6c1b589d600b4295528d3fcac161b581f739095b99cd6c768b7e16e89ff"
        hash = "883f48ed4e9646da078cabf6b8b4946d9f199660262502650f76450ecf60ddd5"
        hash = "50389c3b95a9de00220fc554258fda1fef01c62dad849e66c8a92fc749523457"
        hash = "c4ab4319a77b751a45391aa01cde2d765b095b0e3f6a92b0b8626d5c7e3ad603"
        hash = "df381f04fca2522e2ecba0f5de3f73a655d1540e1cf865970f5fa3bf52d2b297"
        hash = "401388d8b97649672d101bf55694dd175375214386253d0b4b8d8d801a89549c"
        hash = "99fc39a12856cc1a42bb7f90ffc9fe0a5339838b54a63e8f00aa98961c900618"
        hash = "fb031af7aa459ee88a9ca44013a76f6278ad5846aa20e5add4aeb5fab058d0ee"
        hash = "dd5d8a9b4bb406e0b8f868165a1714fe54ffb18e621582210f96f6e5ae850b33"
        hash = "0ff05e6695074f98b0dee6200697a997c509a652f746d2c1c92c0b0a0552ca47"

        id = "9ae920e2-17c8-58fd-8566-90d461a54943"
    strings:
        // "e\x4a\x48\x5a\x70\x63\62\154\x30\131\171\101\x39\111\x43\x52\x66\x51\
        //$mix = /['"]\\x?[0-9a-f]{2,3}[\\\w]{2,20}\\\d{1,3}[\\\w]{2,20}\\x[0-9a-f]{2}\\/ ascii
        $mix = /['"](\w|\\x?[0-9a-f]{2,3})[\\x0-9a-f]{2,20}\\\d{1,3}[\\x0-9a-f]{2,20}\\x[0-9a-f]{2}\\/ ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" ascii
        $no_xml2 = "<?xml-stylesheet" ascii
        $no_asp1 = "<%@LANGUAGE" ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ ascii
        $php_new2 = "<?php" ascii
        $php_new3 = "<script language=\"php" ascii

condition:
    any of them
}

rule WEBSHELL_PHP_OBFUSC_Tiny
{
    meta:
        description = "PHP webshell obfuscated"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/12"
        modified = "2024-03-11"
        hash = "b7b7aabd518a2f8578d4b1bc9a3af60d155972f1"
        hash = "694ec6e1c4f34632a9bd7065f73be473"
        hash = "5c871183444dbb5c8766df6b126bd80c624a63a16cc39e20a0f7b002216b2ba5"

        id = "d78e495f-54d2-5f5f-920f-fb6612afbca3"
    strings:
        // 'ev'.'al'
        $obf1 = /\w'\.'\w/ ascii
        $obf2 = /\w\"\.\"\w/ ascii
        $obf3 = "].$" ascii

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"

        //strings from private rule capa_php_old_safe
        $php_short = "<?" ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" ascii
        $no_xml2 = "<?xml-stylesheet" ascii
        $no_asp1 = "<%@LANGUAGE" ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ ascii
        $php_new2 = "<?php" ascii
        $php_new3 = "<script language=\"php" ascii

        //strings from private rule capa_php_payload
        // \([^)] to avoid matching on e.g. eval() in comments
        $cpayload1 = /\beval[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload2 = /\bexec[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload3 = /\bshell_exec[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload4 = /\bpassthru[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload5 = /\bsystem[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload6 = /\bpopen[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload7 = /\bproc_open[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload8 = /\bpcntl_exec[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload9 = /\bassert[\n\t ]{0,500}\([^)0]/ ascii
        $cpayload10 = /\bpreg_replace[\n\t ]{0,500}\([^\)]{1,100}\/[ismxADSUXju]{0,11}(e|\\x65)/ ascii
        $cpayload12 = /\bmb_ereg_replace[\t ]{0,500}\([^\)]{1,100}'e'/ ascii
        $cpayload13 = /\bmb_eregi_replace[\t ]{0,500}\([^\)]{1,100}'e'/ ascii
        $cpayload20 = /\bcreate_function[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload21 = /\bReflectionFunction[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]{0,500}[,}\)]/ ascii

        $m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]{0,500}(\([^\)]|\/\*)/ ascii
        $m_cpayload_preg_filter2 = "'|.*|e'" ascii
        // TODO backticks

condition:
    any of them
}

rule WEBSHELL_PHP_OBFUSC_Str_Replace
{
    meta:
        description = "PHP webshell which eval()s obfuscated string"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/12"
        modified = "2023-04-05"
        hash = "691305753e26884d0f930cda0fe5231c6437de94"
        hash = "7efd463aeb5bf0120dc5f963b62463211bd9e678"
        hash = "fb655ddb90892e522ae1aaaf6cd8bde27a7f49ef"
        hash = "d1863aeca1a479462648d975773f795bb33a7af2"
        hash = "4d31d94b88e2bbd255cf501e178944425d40ee97"
        hash = "e1a2af3477d62a58f9e6431f5a4a123fb897ea80"

        id = "1f5b93c9-bdeb-52c7-a99a-69869634a574"
    strings:
        $payload1 = "str_replace" fullword ascii
        $payload2 = "function" fullword ascii
        $goto = "goto" fullword ascii
        //$hex  = "\\x"
        $chr1  = "\\61" ascii
        $chr2  = "\\112" ascii
        $chr3  = "\\120" ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" ascii
        $no_xml2 = "<?xml-stylesheet" ascii
        $no_asp1 = "<%@LANGUAGE" ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ ascii
        $php_new2 = "<?php" ascii
        $php_new3 = "<script language=\"php" ascii

condition:
    any of them
}

rule WEBSHELL_PHP_OBFUSC_Fopo
{
    meta:
        description = "PHP webshell which eval()s obfuscated string"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        hash = "fbcff8ea5ce04fc91c05384e847f2c316e013207"
        hash = "6da57ad8be1c587bb5cc8a1413f07d10fb314b72"
        hash = "a698441f817a9a72908a0d93a34133469f33a7b34972af3e351bdccae0737d99"
        date = "2021/01/12"
        modified = "2023-04-05"

        id = "a298e99d-1ba8-58c8-afb9-fc988ea91e9a"
    strings:
        $payload = /(\beval[\t ]{0,500}\([^)]|\bassert[\t ]{0,500}\([^)])/ ascii
        // ;@eval(
        $one1 = "7QGV2YWwo" ascii
        $one2 = "tAZXZhbC" ascii
        $one3 = "O0BldmFsK" ascii
        $one4 = "sAQABlAHYAYQBsACgA" ascii
        $one5 = "7AEAAZQB2AGEAbAAoA" ascii
        $one6 = "OwBAAGUAdgBhAGwAKA" ascii
        // ;@assert(
        $two1 = "7QGFzc2VydC" ascii
        $two2 = "tAYXNzZXJ0K" ascii
        $two3 = "O0Bhc3NlcnQo" ascii
        $two4 = "sAQABhAHMAcwBlAHIAdAAoA" ascii
        $two5 = "7AEAAYQBzAHMAZQByAHQAKA" ascii
        $two6 = "OwBAAGEAcwBzAGUAcgB0ACgA" ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" ascii
        $no_xml2 = "<?xml-stylesheet" ascii
        $no_asp1 = "<%@LANGUAGE" ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ ascii
        $php_new2 = "<?php" ascii
        $php_new3 = "<script language=\"php" ascii

condition:
    any of them
}

rule WEBSHELL_PHP_Gzinflated
{
    meta:
        description = "PHP webshell which directly eval()s obfuscated string"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/12"
        modified = "2023-07-05"
        hash = "49e5bc75a1ec36beeff4fbaeb16b322b08cf192d"
        hash = "6f36d201cd32296bad9d5864c7357e8634f365cc"
        hash = "ab10a1e69f3dfe7c2ad12b2e6c0e66db819c2301"
        hash = "a6cf337fe11fe646d7eee3d3f09c7cb9643d921d"
        hash = "07eb6634f28549ebf26583e8b154c6a579b8a733"

        id = "9cf99ae4-9f7c-502f-9294-b531002953d6"
    strings:
        $payload2 = /eval\s?\(\s?("\?>".)?gzinflate\s?\(\s?base64_decode\s?\(/ ascii 
        $payload4 = /eval\s?\(\s?("\?>".)?gzuncompress\s?\(\s?(base64_decode|gzuncompress)/ ascii 
        $payload6 = /eval\s?\(\s?("\?>".)?gzdecode\s?\(\s?base64_decode\s?\(/ ascii 
        $payload7 = /eval\s?\(\s?base64_decode\s?\(/ ascii
        $payload8 = /eval\s?\(\s?pack\s?\(/ ascii

        // api.telegram
        $fp1 = "YXBpLnRlbGVncmFtLm9"

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"

        //strings from private rule capa_php_old_safe
        $php_short = "<?" ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" ascii
        $no_xml2 = "<?xml-stylesheet" ascii
        $no_asp1 = "<%@LANGUAGE" ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ ascii
        $php_new2 = "<?php" ascii
        $php_new3 = "<script language=\"php" ascii

condition:
    any of them
}

rule WEBSHELL_PHP_OBFUSC_3
{
    meta:
        description = "PHP webshell which eval()s obfuscated string"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 70
        date = "2021/04/17"
        modified = "2024-12-09"
        hash = "11bb1fa3478ec16c00da2a1531906c05e9c982ea"
        hash = "d6b851cae249ea6744078393f622ace15f9880bc"
        hash = "14e02b61905cf373ba9234a13958310652a91ece"
        hash = "6f97f607a3db798128288e32de851c6f56e91c1d"

        id = "f2017e6f-0623-53ff-aa26-a479f3a02024"
    strings:
        $obf1 = "chr(" ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" ascii
        $no_xml2 = "<?xml-stylesheet" ascii
        $no_asp1 = "<%@LANGUAGE" ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ ascii
        $php_new2 = "<?php" ascii
        $php_new3 = "<script language=\"php" ascii

        //strings from private rule capa_php_callback
        // the end is 1. ( followed by anything but a direct closing ) 2. /* for the start of an obfuscation comment
        $callback1 = /\bob_start[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback2 = /\barray_diff_uassoc[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback3 = /\barray_diff_ukey[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback4 = /\barray_filter[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback5 = /\barray_intersect_uassoc[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback6 = /\barray_intersect_ukey[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback7 = /\barray_map[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback8 = /\barray_reduce[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback9 = /\barray_udiff_assoc[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback10 = /\barray_udiff_uassoc[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback11 = /\barray_udiff[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback12 = /\barray_uintersect_assoc[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback13 = /\barray_uintersect_uassoc[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback14 = /\barray_uintersect[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback15 = /\barray_walk_recursive[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback16 = /\barray_walk[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback17 = /\bassert_options[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback18 = /\buasort[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback19 = /\buksort[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback20 = /\busort[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback21 = /\bpreg_replace_callback[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback22 = /\bspl_autoload_register[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback23 = /\biterator_apply[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback24 = /\bcall_user_func[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback25 = /\bcall_user_func_array[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback26 = /\bregister_shutdown_function[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback27 = /\bregister_tick_function[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback28 = /\bset_error_handler[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback29 = /\bset_exception_handler[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback30 = /\bsession_set_save_handler[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback31 = /\bsqlite_create_aggregate[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback32 = /\bsqlite_create_function[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $callback33 = /\bmb_ereg_replace_callback[\n\t ]{0,500}(\([^)]|\/\*)/ ascii

        $m_callback1 = /\bfilter_var[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $m_callback2 = "FILTER_CALLBACK" fullword ascii

        $cfp1 = /ob_start\(['\"]ob_gzhandler/ ascii
        $cfp2 = "IWPML_Backend_Action_Loader" ascii 
        $cfp3 = "<?phpclass WPML" ascii
        $cfp4 = "      return implode('', "

        //strings from private rule capa_php_payload
        // \([^)] to avoid matching on e.g. eval() in comments
        $cpayload1 = /\beval[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload2 = /\bexec[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload3 = /\bshell_exec[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload4 = /\bpassthru[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload5 = /\bsystem[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload6 = /\bpopen[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload7 = /\bproc_open[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload8 = /\bpcntl_exec[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload9 = /\bassert[\n\t ]{0,500}\([^)0]/ ascii
        $cpayload10 = /\bpreg_replace[\n\t ]{0,500}\([^\)]{1,100}\/[ismxADSUXju]{0,11}(e|\\x65)/ ascii
        $cpayload12 = /\bmb_ereg_replace[\t ]{0,500}\([^\)]{1,100}'e'/ ascii
        $cpayload13 = /\bmb_eregi_replace[\t ]{0,500}\([^\)]{1,100}'e'/ ascii
        $cpayload20 = /\bcreate_function[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload21 = /\bReflectionFunction[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]{0,500}[,}\)]/ ascii

        $m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]{0,500}(\([^\)]|\/\*)/ ascii
        $m_cpayload_preg_filter2 = "'|.*|e'" ascii
        // TODO backticks

        //strings from private rule capa_php_obfuscation_single
        $cobfs1 = "gzinflate" fullword ascii
        $cobfs2 = "gzuncompress" fullword ascii
        $cobfs3 = "gzdecode" fullword ascii
        $cobfs4 = "base64_decode" fullword ascii
        $cobfs5 = "pack" fullword ascii
        $cobfs6 = "undecode" fullword ascii

        //strings from private rule capa_gen_sus

        // these strings are just a bit suspicious, so several of them are needed, depending on filesize
        $gen_bit_sus1  = /:\s{0,20}eval}/ ascii
        $gen_bit_sus2  = /\.replace\(\/\w\/g/ ascii
        $gen_bit_sus6  = "self.delete"
        $gen_bit_sus9  = "\"cmd /c"
        $gen_bit_sus10 = "\"cmd\""
        $gen_bit_sus11 = "\"cmd.exe"
        $gen_bit_sus12 = "%comspec%" ascii
        $gen_bit_sus13 = "%COMSPEC%" ascii
        //TODO:$gen_bit_sus12 = ".UserName"
        $gen_bit_sus18 = "Hklm.GetValueNames();" 
        // bonus string for proxylogon exploiting webshells
        $gen_bit_sus19 = "http://schemas.microsoft.com/exchange/" ascii
        $gen_bit_sus21 = "\"upload\"" ascii
        $gen_bit_sus22 = "\"Upload\"" ascii
        $gen_bit_sus23 = "UPLOAD" fullword ascii
        $gen_bit_sus24 = "fileupload" ascii
        $gen_bit_sus25 = "file_upload" ascii
        // own  or base32 func
        $gen_bit_sus29 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" fullword ascii
        $gen_bit_sus29b = "abcdefghijklmnopqrstuvwxyz234567" fullword ascii
        $gen_bit_sus30 = "serv-u" ascii
        $gen_bit_sus31 = "Serv-u" ascii
        $gen_bit_sus32 = "Army" fullword ascii
        // single letter paramweter
        $gen_bit_sus33 = /\$_(GET|POST|REQUEST)\["\w"\]/ fullword ascii
        $gen_bit_sus34 = "Content-Transfer-Encoding: Binary" ascii
        $gen_bit_sus35 = "crack" fullword ascii

        $gen_bit_sus44 = "<pre>" ascii
        $gen_bit_sus45 = "<PRE>" ascii
        $gen_bit_sus46 = "shell_" ascii
        //fp: $gen_bit_sus47 = "Shell" fullword ascii
        $gen_bit_sus50 = "bypass" ascii
        $gen_bit_sus52 = " ^ $" ascii
        $gen_bit_sus53 = ".ssh/authorized_keys" ascii
        $gen_bit_sus55 = /\w'\.'\w/ ascii
        $gen_bit_sus56 = /\w\"\.\"\w/ ascii
        $gen_bit_sus57 = "dumper" ascii
        $gen_bit_sus59 = "'cmd'" ascii
        $gen_bit_sus60 = "\"execute\"" ascii
        $gen_bit_sus61 = "/bin/sh" ascii
        $gen_bit_sus62 = "Cyber" ascii
        $gen_bit_sus63 = "portscan" fullword ascii
        //$gen_bit_sus64 = "\"command\"" fullword ascii
        //$gen_bit_sus65 = "'command'" fullword ascii
        $gen_bit_sus66 = "whoami" fullword ascii
        $gen_bit_sus67 = "$password='" fullword ascii
        $gen_bit_sus68 = "$password=\"" fullword ascii
        $gen_bit_sus69 = "$cmd" fullword ascii
        $gen_bit_sus70 = "\"?>\"." fullword ascii
        $gen_bit_sus71 = "Hacking" fullword ascii
        $gen_bit_sus72 = "hacking" fullword ascii
        $gen_bit_sus73 = ".htpasswd" ascii
        $gen_bit_sus74 = /\btouch\(\$[^,]{1,30},/ ascii

        // very suspicious strings, one is enough
        $gen_much_sus7  = "Web Shell" 
        $gen_much_sus8  = "WebShell" 
        $gen_much_sus3  = "hidded shell"
        $gen_much_sus4  = "WScript.Shell.1" 
        $gen_much_sus5  = "AspExec"
        $gen_much_sus14 = "\\pcAnywhere\\" 
        $gen_much_sus15 = "antivirus" 
        $gen_much_sus16 = "McAfee" 
        $gen_much_sus17 = "nishang"
        $gen_much_sus18 = "\"unsafe" fullword ascii
        $gen_much_sus19 = "'unsafe" fullword ascii
        $gen_much_sus24 = "exploit" fullword ascii
        $gen_much_sus25 = "Exploit" fullword ascii
        $gen_much_sus26 = "TVqQAAMAAA" ascii
        $gen_much_sus30 = "Hacker" ascii
        $gen_much_sus31 = "HACKED" fullword ascii
        $gen_much_sus32 = "hacked" fullword ascii
        $gen_much_sus33 = "hacker" ascii
        $gen_much_sus34 = "grayhat" ascii
        $gen_much_sus35 = "Microsoft FrontPage" ascii
        $gen_much_sus36 = "Rootkit" ascii
        $gen_much_sus37 = "rootkit" ascii
        $gen_much_sus38 = "/*-/*-*/" ascii
        $gen_much_sus39 = "u\"+\"n\"+\"s" ascii
        $gen_much_sus40 = "\"e\"+\"v" ascii
        $gen_much_sus41 = "a\"+\"l\"" ascii
        $gen_much_sus42 = "\"+\"(\"+\"" ascii
        $gen_much_sus43 = "q\"+\"u\"" ascii
        $gen_much_sus44 = "\"u\"+\"e" ascii
        $gen_much_sus45 = "/*//*/" ascii
        $gen_much_sus46 = "(\"/*/\"" ascii
        $gen_much_sus47 = "eval(eval(" ascii
        // self remove
        $gen_much_sus48 = "unlink(__FILE__)" ascii
        $gen_much_sus49 = "Shell.Users" ascii
        $gen_much_sus50 = "PasswordType=Regular" ascii
        $gen_much_sus51 = "-Expire=0" ascii
        $gen_much_sus60 = "_=$$_" ascii
        $gen_much_sus61 = "_=$$_" ascii
        $gen_much_sus62 = "++;$" ascii
        $gen_much_sus63 = "++; $" ascii
        $gen_much_sus64 = "_.=$_" ascii
        $gen_much_sus70 = "-perm -04000" ascii
        $gen_much_sus71 = "-perm -02000" ascii
        $gen_much_sus72 = "grep -li password" ascii
        $gen_much_sus73 = "-name config.inc.php" ascii
        // touch without parameters sets the time to now, not malicious and gives fp
        $gen_much_sus75 = "password crack" ascii
        $gen_much_sus76 = "mysqlDll.dll" ascii
        $gen_much_sus77 = "net user" ascii
        $gen_much_sus80 = "fopen(\".htaccess\",\"w" ascii
        $gen_much_sus81 = /strrev\(['"]/ ascii
        $gen_much_sus82 = "PHPShell" fullword ascii
        $gen_much_sus821= "PHP Shell" fullword ascii
        $gen_much_sus83 = "phpshell" fullword ascii
        $gen_much_sus84 = "PHPshell" fullword ascii
        $gen_much_sus87 = "deface" ascii
        $gen_much_sus88 = "Deface" ascii
        $gen_much_sus89 = "backdoor" ascii
        $gen_much_sus90 = "r00t" fullword ascii
        $gen_much_sus91 = "xp_cmdshell" fullword ascii
        $gen_much_sus92 = "base64_decode(base64_decode(" fullword ascii
        $gen_much_sus93 = "eval(\"/*" ascii
        $gen_much_sus94 = "=$_COOKIE;" ascii

        $gif = { 47 49 46 38 }


condition:
    any of them
}

rule WEBSHELL_PHP_Includer_Eval
{
    meta:
        description = "PHP webshell which eval()s another included file"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/13"
        modified = "2023-04-05"
        hash = "3a07e9188028efa32872ba5b6e5363920a6b2489"
        hash = "ab771bb715710892b9513b1d075b4e2c0931afb6"
        hash = "202dbcdc2896873631e1a0448098c820c82bcc8385a9f7579a0dc9702d76f580"
        hash = "b51a6d208ec3a44a67cce16dcc1e93cdb06fe150acf16222815333ddf52d4db8"

        id = "995fcc34-f91e-5c9c-97b1-84eed1714d40"
    strings:
        $payload1 = "eval" fullword ascii
        $payload2 = "assert" fullword ascii
        $include1 = "$_FILE" ascii
        $include2 = "include" ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" ascii
        $no_xml2 = "<?xml-stylesheet" ascii
        $no_asp1 = "<%@LANGUAGE" ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ ascii
        $php_new2 = "<?php" ascii
        $php_new3 = "<script language=\"php" ascii

condition:
    any of them
}

rule WEBSHELL_PHP_Includer_Tiny
{
    meta:
        description = "Suspicious: Might be PHP webshell includer, check the included file"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/04/17"
        modified = "2023-07-05"
        hash = "0687585025f99596508783b891e26d6989eec2ba"
        hash = "9e856f5cb7cb901b5003e57c528a6298341d04dc"
        hash = "b3b0274cda28292813096a5a7a3f5f77378b8905205bda7bb7e1a679a7845004"

        id = "9bf96ddc-d984-57eb-9803-0b01890711b5"
    strings:
        $php_include1 = /include\(\$_(GET|POST|REQUEST)\[/ ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" ascii
        $no_xml2 = "<?xml-stylesheet" ascii
        $no_asp1 = "<%@LANGUAGE" ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ ascii
        $php_new2 = "<?php" ascii
        $php_new3 = "<script language=\"php" ascii

condition:
    any of them
}

rule WEBSHELL_PHP_Dynamic
{
    meta:
        description = "PHP webshell using function name from variable, e.g. $a='ev'.'al'; $a($code)"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/01/13"
        modified = "2024-12-09"
        score = 60
        hash = "65dca1e652d09514e9c9b2e0004629d03ab3c3ef"
        hash = "b8ab38dc75cec26ce3d3a91cb2951d7cdd004838"
        hash = "c4765e81550b476976604d01c20e3dbd415366df"
        hash = "2e11ba2d06ebe0aa818e38e24a8a83eebbaae8877c10b704af01bf2977701e73"

        id = "58ad94bc-93c8-509c-9d3a-c9a26538d60c"
    strings:
        $pd_fp1 = "whoops_add_stack_frame" ascii
        $pd_fp2 = "new $ec($code, $mode, $options, $userinfo);" ascii
        $pd_fp3 = "($i)] = 600;" ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" ascii
        $no_xml2 = "<?xml-stylesheet" ascii
        $no_asp1 = "<%@LANGUAGE" ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ ascii
        $php_new2 = "<?php" ascii
        $php_new3 = "<script language=\"php" ascii

        //strings from private rule capa_php_dynamic
        // php variable regex from https://www.php.net/manual/en/language.variables.basics.php
        $dynamic1 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(\$/ ascii
        $dynamic2 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\("/ ascii
        $dynamic3 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\('/ ascii
        $dynamic4 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(str/ ascii
        $dynamic5 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(\)/ ascii
        $dynamic6 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(@/ ascii
        $dynamic7 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(base64_decode/ ascii
        // ${'_'.$_}["_"](${'_'.$_}["__"]
        $dynamic8 = /\$\{[^}]{1,20}}(\[[^\]]{1,20}\])?\(\$\{/ ascii

        $fp1 = { 3C 3F 70 68 70 0A 0A 24 61 28 24 62 20 3D 20 33 2C 20 24 63 29 3B } /* <?php\x0a\x0a$a($b = 3, $c); */
        $fp2 = { 3C 3F 70 68 70 0A 0A 24 61 28 24 62 20 3D 20 33 2C 20 2E 2E 2E 20 24 63 29 3B } /* <?php\x0a\x0a$a($b = 3, ... $c); */
        $fp3 = { 3C 3F 70 68 70 0A 0A 24 61 20 3D 20 6E 65 77 20 73 74 61 74 69 63 3A 3A 24 62 28 29 3B} /* <?php\x0a\x0a$a = new static::$b(); */
        $fp4 = { 3C 3F 70 68 70 0A 0A 24 61 20 3D 20 6E 65 77 20 73 65 6C 66 3A 3A 24 62 28 29 3B } /* <?php\x0a\x0a$a = new self::$b(); */
        $fp5 = { 3C 3F 70 68 70 0A 0A 24 61 20 3D 20 5C 22 7B 24 76 61 72 43 61 6C 6C 61 62 6C 65 28 29 7D 5C 22 3B } /* <?php\x0a\x0a$a = \"{$varCallable()}\"; */
        $fp6 = "// TODO error about missing expression" /* <?php\x0a// TODO error about missing expression\x0a$a($b = 3, $c,); */
        $fp7 = "// This is an invalid location for an attribute, "
        $fp8 = "/* Auto-generated from php/php-langspec tests */"
        $fp_dynamic1 = /"\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(\$/ ascii // e.g. echo 
condition:
    any of them
}

rule WEBSHELL_PHP_Dynamic_Big
{
    meta:
        description = "PHP webshell using $a($code) for kind of eval with encoded blob to decode, e.g. b374k"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/02/07"
        modified = "2025-08-18"
        score = 50
        hash = "6559bfc4be43a55c6bb2bd867b4c9b929713d3f7f6de8111a3c330f87a9b302c"
        hash = "9e82c9c2fa64e26fd55aa18f74759454d89f968068d46b255bd4f41eb556112e"
        hash = "6def5296f95e191a9c7f64f7d8ac5c529d4a4347ae484775965442162345dc93"
        hash = "dadfdc4041caa37166db80838e572d091bb153815a306c8be0d66c9851b98c10"
        hash = "0a4a292f6e08479c04e5c4fdc3857eee72efa5cd39db52e4a6e405bf039928bd"
        hash = "4326d10059e97809fb1903eb96fd9152cc72c376913771f59fa674a3f110679e"
        hash = "b49d0f942a38a33d2b655b1c32ac44f19ed844c2479bad6e540f69b807dd3022"
        hash = "575edeb905b434a3b35732654eedd3afae81e7d99ca35848c509177aa9bf9eef"
        hash = "ee34d62e136a04e2eaf84b8daa12c9f2233a366af83081a38c3c973ab5e2c40f"

        id = "a5caab93-7b94-59d7-bbca-f9863e81b9e5"
    strings:
        //strings from private rule capa_bin_files
        $dex1 = "dex\n0"
        $dex2 = "dey\n0"
        $pack  = { 50 41 43 4b 00 00 00 02 00 }

        //strings from private rule capa_php_new_long
        // no <?=
        $new_php2 = "<?php" ascii
        $new_php3 = "<script language=\"php" ascii
        $php_short = "<?"

        //strings from private rule capa_php_dynamic
        // php variable regex from https://www.php.net/manual/en/language.variables.basics.php
        $dynamic1 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(\$/ ascii
        $dynamic2 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\("/ ascii
        $dynamic3 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\('/ ascii
        $dynamic4 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(str/ ascii
        $dynamic5 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(\)/ ascii
        $dynamic6 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(@/ ascii
        $dynamic7 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(base64_decode/ ascii
        $dynamic8 = "eval(" ascii

        //strings from private rule capa_gen_sus

        // these strings are just a bit suspicious, so several of them are needed, depending on filesize
        $gen_bit_sus1  = /:\s{0,20}eval}/ ascii
        $gen_bit_sus2  = /\.replace\(\/\w\/g/ ascii
        $gen_bit_sus6  = "self.delete"
        $gen_bit_sus9  = "\"cmd /c"
        $gen_bit_sus10 = "\"cmd\""
        $gen_bit_sus11 = "\"cmd.exe"
        $gen_bit_sus12 = "%comspec%" ascii
        $gen_bit_sus13 = "%COMSPEC%" ascii
        //TODO:$gen_bit_sus12 = ".UserName"
        $gen_bit_sus18 = "Hklm.GetValueNames();" 
        // bonus string for proxylogon exploiting webshells
        $gen_bit_sus19 = "http://schemas.microsoft.com/exchange/" ascii
        $gen_bit_sus21 = "\"upload\"" ascii
        $gen_bit_sus22 = "\"Upload\"" ascii
        $gen_bit_sus23 = "UPLOAD" fullword ascii
        $gen_bit_sus24 = "fileupload" ascii
        $gen_bit_sus25 = "file_upload" ascii
        $gen_bit_sus27 = "zuncomp" ascii
        $gen_bit_sus28 = "ase6" ascii
        // own  or base32 func
        $gen_bit_sus29 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" fullword ascii
        $gen_bit_sus29b = "abcdefghijklmnopqrstuvwxyz234567" fullword ascii
        $gen_bit_sus30 = "serv-u" ascii
        $gen_bit_sus31 = "Serv-u" ascii
        $gen_bit_sus32 = "Army" fullword ascii
        // single letter paramweter
        $gen_bit_sus33 = /\$_(GET|POST|REQUEST)\["\w"\]/ fullword ascii
        $gen_bit_sus34 = "Content-Transfer-Encoding: Binary" ascii
        $gen_bit_sus35 = "crack" fullword ascii

        $gen_bit_sus44 = "<pre>" ascii
        $gen_bit_sus45 = "<PRE>" ascii
        $gen_bit_sus46 = "shell_" ascii
        //fp: $gen_bit_sus47 = "Shell" fullword ascii
        $gen_bit_sus50 = "bypass" ascii
        $gen_bit_sus52 = " ^ $" ascii
        $gen_bit_sus53 = ".ssh/authorized_keys" ascii
        $gen_bit_sus55 = /\w'\.'\w/ ascii
        $gen_bit_sus56 = /\w\"\.\"\w/ ascii
        $gen_bit_sus57 = "dumper" ascii
        $gen_bit_sus59 = "'cmd'" ascii
        $gen_bit_sus60 = "\"execute\"" ascii
        $gen_bit_sus61 = "/bin/sh" ascii
        $gen_bit_sus62 = "Cyber" ascii
        $gen_bit_sus63 = "portscan" fullword ascii
        $gen_bit_sus65 = "whoami" fullword ascii
        $gen_bit_sus67 = "$password='" fullword ascii
        $gen_bit_sus68 = "$password=\"" fullword ascii
        $gen_bit_sus69 = "$cmd" fullword ascii
        $gen_bit_sus70 = "\"?>\"." fullword ascii
        $gen_bit_sus71 = "Hacking" fullword ascii
        $gen_bit_sus72 = "hacking" fullword ascii
        $gen_bit_sus73 = ".htpasswd" ascii
        $gen_bit_sus74 = /\btouch\(\$[^,]{1,30},/ ascii
        $gen_bit_sus99 = "$password = " ascii
        $gen_bit_sus100 = "();$" ascii

        // very suspicious strings, one is enough
        $gen_much_sus7  = "Web Shell" 
        $gen_much_sus8  = "WebShell" 
        $gen_much_sus3  = "hidded shell"
        $gen_much_sus4  = "WScript.Shell.1" 
        $gen_much_sus5  = "AspExec"
        $gen_much_sus14 = "\\pcAnywhere\\" 
        $gen_much_sus15 = "antivirus" 
        $gen_much_sus16 = "McAfee" 
        $gen_much_sus17 = "nishang"
        $gen_much_sus18 = "\"unsafe" fullword ascii
        $gen_much_sus19 = "'unsafe" fullword ascii
        $gen_much_sus24 = "exploit" fullword ascii
        $gen_much_sus25 = "Exploit" fullword ascii
        $gen_much_sus26 = "TVqQAAMAAA" ascii
        $gen_much_sus30 = "Hacker" ascii
        $gen_much_sus31 = "HACKED" fullword ascii
        $gen_much_sus32 = "hacked" fullword ascii
        $gen_much_sus33 = "hacker" ascii
        $gen_much_sus34 = "grayhat" ascii
        $gen_much_sus35 = "Microsoft FrontPage" ascii
        $gen_much_sus36 = "Rootkit" ascii
        $gen_much_sus37 = "rootkit" ascii
        $gen_much_sus38 = "/*-/*-*/" ascii
        $gen_much_sus39 = "u\"+\"n\"+\"s" ascii
        $gen_much_sus40 = "\"e\"+\"v" ascii
        $gen_much_sus41 = "a\"+\"l\"" ascii
        $gen_much_sus42 = "\"+\"(\"+\"" ascii
        $gen_much_sus43 = "q\"+\"u\"" ascii
        $gen_much_sus44 = "\"u\"+\"e" ascii
        $gen_much_sus45 = "/*//*/" ascii
        $gen_much_sus46 = "(\"/*/\"" ascii
        $gen_much_sus47 = "eval(eval(" ascii
        // self remove
        $gen_much_sus48 = "unlink(__FILE__)" ascii
        $gen_much_sus49 = "Shell.Users" ascii
        $gen_much_sus50 = "PasswordType=Regular" ascii
        $gen_much_sus51 = "-Expire=0" ascii
        $gen_much_sus60 = "_=$$_" ascii
        $gen_much_sus61 = "_=$$_" ascii
        $gen_much_sus62 = "++;$" ascii
        $gen_much_sus63 = "++; $" ascii
        $gen_much_sus64 = "_.=$_" ascii
        $gen_much_sus70 = "-perm -04000" ascii
        $gen_much_sus71 = "-perm -02000" ascii
        $gen_much_sus72 = "grep -li password" ascii
        $gen_much_sus73 = "-name config.inc.php" ascii
        // touch without parameters sets the time to now, not malicious and gives fp
        $gen_much_sus75 = "password crack" ascii
        $gen_much_sus76 = "mysqlDll.dll" ascii
        $gen_much_sus77 = "net user" ascii
        $gen_much_sus80 = "fopen(\".htaccess\",\"w" ascii
        $gen_much_sus81 = /strrev\(['"]/ ascii
        $gen_much_sus82 = "PHPShell" fullword ascii
        $gen_much_sus821= "PHP Shell" fullword ascii
        $gen_much_sus83 = "phpshell" fullword ascii
        $gen_much_sus84 = "PHPshell" fullword ascii
        $gen_much_sus87 = "deface" ascii
        $gen_much_sus88 = "Deface" ascii
        $gen_much_sus89 = "backdoor" ascii
        $gen_much_sus90 = "r00t" fullword ascii
        $gen_much_sus91 = "xp_cmdshell" fullword ascii
        $gen_much_sus92 = "DEFACE" fullword ascii
        $gen_much_sus93 = "Bypass" fullword ascii
        $gen_much_sus94 = /eval\s{2,20}\(/ ascii
        $gen_much_sus100 = "rot13" ascii
        $gen_much_sus101 = "ini_set('error_log'" ascii
        $gen_much_sus102 = "base64_decode(base64_decode(" ascii
        $gen_much_sus103 = "=$_COOKIE;" ascii
        // {1}.$ .. |{9}.$
        $gen_much_sus104 = { C0 A6 7B 3? 7D 2E 24 }
        $gen_much_sus105 = "$GLOBALS[\"__" ascii
        // those calculations don't make really sense :)
        $gen_much_sus106 = ")-0)" ascii
        $gen_much_sus107 = "-0)+" ascii
        $gen_much_sus108 = "+0)+" ascii
        $gen_much_sus109 = "+(0/" ascii
        $gen_much_sus110 = "+(0+" ascii
        $gen_much_sus111 = "extract($_REQUEST)" ascii
        $gen_much_sus112 = "<?php\t\t\t\t\t\t\t\t\t\t\t" ascii
        $gen_much_sus113 = "\t\t\t\t\t\t\t\t\t\t\textract" ascii
        $gen_much_sus114 = "\" .\"" ascii
        $gen_much_sus115 = "end($_POST" ascii

        $weevely1 = /';\n\$\w\s?=\s?'/ ascii
        $weevely2 = /';\x0d\n\$\w\s?=\s?'/ ascii // same with \r\n
        $weevely3 = /';\$\w{1,2}='/ wide ascii
        $weevely4 = "str_replace" fullword ascii

        $gif = { 47 49 46 38 }

        $fp1 = "# Some examples from obfuscated malware:" ascii
        $fp2 = "* @package   PHP_CodeSniffer" ascii
        $fp3 = ".jQuery===" ascii
        $fp4 = "* @param string $lstat encoded LStat string" ascii
        $fp5 = "' => array('horde:"
        $fp6 = "$messages['fileuploaderror'] = '"
condition:
    any of them
}

rule WEBSHELL_PHP_Encoded_Big
{
    meta:
        description = "PHP webshell using some kind of eval with encoded blob to decode, which is checked with YARAs math.entropy module"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/02/07"
        modified = "2024-12-16"
        score = 50
        hash = "1d4b374d284c12db881ba42ee63ebce2759e0b14"
        hash = "fc0086caee0a2cd20609a05a6253e23b5e3245b8"
        hash = "b15b073801067429a93e116af1147a21b928b215"
        hash = "74c92f29cf15de34b8866db4b40748243fb938b4"
        hash = "042245ee0c54996608ff8f442c8bafb8"

        id = "c3bb7b8b-c554-5802-8955-c83722498f8b"
    strings:

        //strings from private rule capa_php_new
        $new_php1 = /<\?=[\w\s@$]/ ascii
        $new_php2 = "<?php" ascii
        $new_php3 = "<script language=\"php" ascii
        $php_short = "<?"

        //strings from private rule capa_php_payload
        // \([^)] to avoid matching on e.g. eval() in comments
        $cpayload1 = /\beval[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload2 = /\bexec[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload3 = /\bshell_exec[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload4 = /\bpassthru[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload6 = /\bpopen[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload7 = /\bproc_open[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload8 = /\bpcntl_exec[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload9 = /\bassert[\n\t ]{0,500}\([^)0]/ ascii
        $cpayload10 = /\bpreg_replace[\n\t ]{0,500}\([^\)]{1,100}\/[ismxADSUXju]{0,11}(e|\\x65)/ ascii
        $cpayload12 = /\bmb_ereg_replace[\t ]{0,500}\([^\)]{1,100}'e'/ ascii
        $cpayload13 = /\bmb_eregi_replace[\t ]{0,500}\([^\)]{1,100}'e'/ ascii
        $cpayload20 = /\bcreate_function[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload21 = /\bReflectionFunction[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]{0,500}[,}\)]/ ascii

        $m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]{0,500}(\([^\)]|\/\*)/ ascii
        $m_cpayload_preg_filter2 = "'|.*|e'" ascii
        // TODO backticks

condition:
    any of them
}

rule WEBSHELL_PHP_Generic_Backticks
{
    meta:
        description = "Generic PHP webshell which uses backticks directly on user input"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "339f32c883f6175233f0d1a30510caa52fdcaa37"
        hash = "8db86ad90883cd208cf86acd45e67c03f994998804441705d690cb6526614d00"
        hash = "af987b0eade03672c30c095cee0c7c00b663e4b3c6782615fb7e430e4a7d1d75"
        hash = "67339f9e70a17af16cf51686918cbe1c0604e129950129f67fe445eaff4b4b82"
        hash = "144e242a9b219c5570973ca26d03e82e9fbe7ba2773305d1713288ae3540b4ad"
        hash = "8db86ad90883cd208cf86acd45e67c03f994998804441705d690cb6526614d00"

        id = "b2f1d8d0-8668-5641-8ce9-c8dd71f51f58"
    strings:
        $backtick = /`\s*\{?\$(_POST\[|_GET\[|_REQUEST\[|_SERVER\['HTTP_)/ ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" ascii
        $no_xml2 = "<?xml-stylesheet" ascii
        $no_asp1 = "<%@LANGUAGE" ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ ascii
        $php_new2 = "<?php" ascii
        $php_new3 = "<script language=\"php" ascii

condition:
    any of them
}

rule WEBSHELL_PHP_Generic_Backticks_OBFUSC
{
    meta:
        description = "Generic PHP webshell which uses backticks directly on user input"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "23dc299f941d98c72bd48659cdb4673f5ba93697"
        hash = "e3f393a1530a2824125ecdd6ac79d80cfb18fffb89f470d687323fb5dff0eec1"
        hash = "1e75914336b1013cc30b24d76569542447833416516af0d237c599f95b593f9b"
        hash = "8db86ad90883cd208cf86acd45e67c03f994998804441705d690cb6526614d00"

        id = "5ecb329f-0755-536d-8bfa-e36158474a0b"
    strings:
        $s1 = /echo[\t ]{0,500}\(?`\$/ ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" ascii
        $no_xml2 = "<?xml-stylesheet" ascii
        $no_asp1 = "<%@LANGUAGE" ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ ascii
        $php_new2 = "<?php" ascii
        $php_new3 = "<script language=\"php" ascii

condition:
    any of them
}

rule WEBSHELL_PHP_By_String_Known_Webshell
{
    meta:
        description = "Known PHP Webshells which contain unique strings, lousy rule for low hanging fruits. Most are catched by other rules in here but maybe these catch different versions."
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021-01-09"
        modified = "2025-08-18"
        score = 70
        hash = "d889da22893536d5965541c30896f4ed4fdf461d"
        hash = "10f4988a191774a2c6b85604344535ee610b844c1708602a355cf7e9c12c3605"
        hash = "7b6471774d14510cf6fa312a496eed72b614f6fc"
        hash = "decda94d40c3fd13dab21e197c8d05f48020fa498f4d0af1f60e29616009e9bf"
        hash = "ef178d332a4780e8b6db0e772aded71ac1a6ed09b923cc359ba3c4efdd818acc"
        hash = "a7a937c766029456050b22fa4218b1f2b45eef0db59b414f79d10791feca2c0b"
        hash = "e7edd380a1a2828929fbde8e7833d6e3385f7652ea6b352d26b86a1e39130ee8"
        hash = "0038946739956c80d75fa9eeb1b5c123b064bbb9381d164d812d72c7c5d13cac"
        hash = "3a7309bad8a5364958081042b5602d82554b97eca04ee8fdd8b671b5d1ddb65d"
        hash = "a78324b9dc0b0676431af40e11bd4e26721a960c55e272d718932bdbb755a098"
        hash = "a27f8cd10cedd20bff51e9a8e19e69361cc8a6a1a700cc64140e66d160be1781"
        hash = "9bbd3462993988f9865262653b35b4151386ed2373592a1e2f8cf0f0271cdb00"
        hash = "459ed1d6f87530910361b1e6065c05ef0b337d128f446253b4e29ae8cc1a3915"
        hash = "12b34d2562518d339ed405fb2f182f95dce36d08fefb5fb67cc9386565f592d1"
        hash = "96d8ca3d269e98a330bdb7583cccdc85eab3682f9b64f98e4f42e55103a71636"
        hash = "312ee17ec9bed4278579443b805c0eb75283f54483d12f9add7d7d9e5f9f6105"
        hash = "15c4e5225ff7811e43506f0e123daee869a8292fc8a38030d165cc3f6a488c95"
        hash = "0c845a031e06925c22667e101a858131bbeb681d78b5dbf446fdd5bca344d765"
        hash = "d52128bcfff5e9a121eab3d76382420c3eebbdb33cd0879fbef7c3426e819695"

        //TODO regex for 96d8ca3d269e98a330bdb7583cccdc85eab3682f9b64f98e4f42e55103a71636 would it be fast enough?

        id = "05ac0e0a-3a19-5c60-b89a-4a300d8c22e7"
    strings:
        $pbs1 = "b374k shell" ascii
        $pbs2 = "b374k/b374k" ascii
        $pbs3 = "\"b374k" ascii
        $pbs4 = "$b374k(\"" ascii
        $pbs5 = "b374k " ascii
        $pbs6 = "0de664ecd2be02cdd54234a0d1229b43" ascii
        $pbs7 = "pwnshell" ascii
        $pbs8 = "reGeorg" fullword ascii
        $pbs9 = "Georg says, 'All seems fine" fullword ascii
        $pbs10 = "My PHP Shell - A very simple web shell" ascii
        $pbs11 = "<title>My PHP Shell <?echo VERSION" ascii
        $pbs12 = "F4ckTeam" fullword ascii
        $pbs15 = "MulCiShell" fullword ascii
        // crawler avoid string
        $pbs30 = "bot|spider|crawler|slurp|teoma|archive|track|snoopy|java|lwp|wget|curl|client|python|libwww" ascii
        // <?=($pbs_=@$_GET[2]).@$_($_GET[1])?>
        $pbs35 = /@\$_GET\s?\[\d\]\)\.@\$_\(\$_GET\s?\[\d\]\)/ ascii
        $pbs36 = /@\$_GET\s?\[\d\]\)\.@\$_\(\$_POST\s?\[\d\]\)/ ascii
        $pbs37 = /@\$_POST\s?\[\d\]\)\.@\$_\(\$_GET\s?\[\d\]\)/ ascii
        $pbs38 = /@\$_POST\[\d\]\)\.@\$_\(\$_POST\[\d\]\)/ ascii
        $pbs39 = /@\$_REQUEST\[\d\]\)\.@\$_\(\$_REQUEST\[\d\]\)/ ascii
        $pbs42 = "array(\"find config.inc.php files\", \"find / -type f -name config.inc.php\")" ascii
        $pbs43 = "$_SERVER[\"\\x48\\x54\\x54\\x50" ascii
        $pbs52 = "preg_replace(\"/[checksql]/e\""
        $pbs53 = "='http://www.zjjv.com'"
        $pbs54 = "=\"http://www.zjjv.com\""

        $pbs60 = /setting\["AccountType"\]\s?=\s?3/
        $pbs61 = "~+d()\"^\"!{+{}"
        $pbs62 = "use function \\eval as "
        $pbs63 = "use function \\assert as "
        $pbs64 = "eval(`/*" ascii
        $pbs65 = "/* Reverse engineering of this file is strictly prohibited. File protected by copyright law and provided under license. */" ascii
        $pbs66 = "Tas9er" fullword ascii
        $pbs67 = "\"TSOP_\";" fullword ascii // reverse _POST
        $pbs68 = "str_rot13('nffreg')" ascii // rot13(assert)
        $pbs69 = "<?=`{$'" ascii
        $pbs70 = "{'_'.$_}[\"_\"](${'_'.$_}[\"_" ascii
        $pbs71 = "\"e45e329feb5d925b\"" ascii
        $pbs72 = "| PHP FILE MANAGER" ascii
        $pbs73 = "\neval(htmlspecialchars_decode(gzinflate(base64_decode($" ascii
        $pbs74 = "/*\n\nShellindir.org\n\n*/" ascii
        $pbs75 = "$shell = 'uname -a; w; id; /bin/sh -i';" ascii
        $pbs76 = "'password' . '/' . 'id' . '/' . " ascii
        $pbs77 = "= create_function /*" ascii
        $pbs78 = "W3LL M!N! SH3LL" ascii
        $pbs79 = "extract($_REQUEST)&&@$" ascii
        $pbs80 = "\"P-h-p-S-p-y\"" ascii
        $pbs81 = "\\x5f\\x72\\x6f\\x74\\x31\\x33" ascii
        $pbs82 = "\\x62\\x61\\x73\\x65\\x36\\x34\\x5f" ascii
        $pbs83 = "*/base64_decode/*" ascii
        $pbs84 = "\n@eval/*" ascii
        $pbs85 = "*/eval/*" ascii
        $pbs86 = "*/ array /*" ascii
        $pbs87 = "2jtffszJe" ascii
        $pbs88 = "edocne_46esab" ascii
        $pbs89 = "eval($_HEADERS" ascii
        $pbs90 = ">Infinity-Sh3ll<" ascii

        $front1 = "<?php eval(" ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" ascii
        $no_xml2 = "<?xml-stylesheet" ascii
        $no_asp1 = "<%@LANGUAGE" ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ ascii
        $php_new2 = "<?php" ascii
        $php_new3 = "<script language=\"php" ascii

        //strings from private rule capa_bin_files
        $dex1 = "dex\n0"
        $dex2 = "dey\n0"
        $pack  = { 50 41 43 4b 00 00 00 02 00 }

condition:
    any of them
}

rule WEBSHELL_PHP_Strings_SUSP
{
    meta:
        description = "typical webshell strings, suspicious"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/01/12"
        modified = "2023-07-05"
        score = 50
        hash = "0dd568dbe946b5aa4e1d33eab1decbd71903ea04"
        hash = "dde2bdcde95730510b22ae8d52e4344997cb1e74"
        hash = "499db4d70955f7d40cf5cbaf2ecaf7a2"
        hash = "281b66f62db5caab2a6eb08929575ad95628a690"
        hash = "1ab3ae4d613b120f9681f6aa8933d66fa38e4886"

        id = "25f25df5-4398-562b-9383-e01ccb17e8de"
    strings:
        $sstring1 = "eval(\"?>\"" ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" ascii
        $no_xml2 = "<?xml-stylesheet" ascii
        $no_asp1 = "<%@LANGUAGE" ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ ascii
        $php_new2 = "<?php" ascii
        $php_new3 = "<script language=\"php" ascii

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"

        //strings from private rule capa_php_input
        $inp1 = "php://input" ascii
        $inp2 = /_GET\s?\[/ ascii
        // for passing $_GET to a function
        $inp3 = /\(\s?\$_GET\s?\)/ ascii
        $inp4 = /_POST\s?\[/ ascii
        $inp5 = /\(\s?\$_POST\s?\)/ ascii
        $inp6 = /_REQUEST\s?\[/ ascii
        $inp7 = /\(\s?\$_REQUEST\s?\)/ ascii
        // PHP automatically adds all the request headers into the $_SERVER global array, prefixing each header name by the "HTTP_" string, so e.g. @eval($_SERVER['HTTP_CMD']) will run any code in the HTTP header CMD
        $inp15 = "_SERVER['HTTP_" ascii
        $inp16 = "_SERVER[\"HTTP_" ascii
        $inp17 = /getenv[\t ]{0,20}\([\t ]{0,20}['"]HTTP_/ ascii
        $inp18 = "array_values($_SERVER)" ascii
        $inp19 = /file_get_contents\("https?:\/\// ascii

condition:
    any of them
}

rule WEBSHELL_PHP_In_Htaccess
{
    meta:
        description = "Use Apache .htaccess to execute php code inside .htaccess"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-07-05"
        hash = "c026d4512a32d93899d486c6f11d1e13b058a713"
        hash = "d79e9b13a32a9e9f3fa36aa1a4baf444bfd2599a"
        hash = "e1d1091fee6026829e037b2c70c228344955c263"
        hash = "c026d4512a32d93899d486c6f11d1e13b058a713"
        hash = "8c9e65cd3ef093cd9c5b418dc5116845aa6602bc92b9b5991b27344d8b3f7ef2"

        id = "0f5edff9-22b2-50c9-ae81-72698ea8e7db"
    strings:
        $hta = "AddType application/x-httpd-php .htaccess" ascii

condition:
    any of them
}

rule WEBSHELL_PHP_Function_Via_Get
{
    meta:
        description = "Webshell which sends eval/assert via GET"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/09"
        modified = "2023-04-05"
        hash = "ce739d65c31b3c7ea94357a38f7bd0dc264da052d4fd93a1eabb257f6e3a97a6"
        hash = "d870e971511ea3e082662f8e6ec22e8a8443ca79"
        hash = "73fa97372b3bb829835270a5e20259163ecc3fdbf73ef2a99cb80709ea4572be"

        id = "5fef1063-2f9f-516e-86f6-cfd98bb05e6e"
    strings:
        $sr0 = /\$_GET\s?\[.{1,30}\]\(\$_GET\s?\[/ ascii
        $sr1 = /\$_POST\s?\[.{1,30}\]\(\$_GET\s?\[/ ascii
        $sr2 = /\$_POST\s?\[.{1,30}\]\(\$_POST\s?\[/ ascii
        $sr3 = /\$_GET\s?\[.{1,30}\]\(\$_POST\s?\[/ ascii
        $sr4 = /\$_REQUEST\s?\[.{1,30}\]\(\$_REQUEST\s?\[/ ascii
        $sr5 = /\$_SERVER\s?\[HTTP_.{1,30}\]\(\$_SERVER\s?\[HTTP_/ ascii

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"

condition:
    any of them
}

rule WEBSHELL_PHP_Writer
{
    meta:
        description = "PHP webshell which only writes an uploaded file to disk"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/04/17"
        modified = "2023-07-05"
        score = 50
        hash = "ec83d69512aa0cc85584973f5f0850932fb1949fb5fb2b7e6e5bbfb121193637"
        hash = "407c15f94a33232c64ddf45f194917fabcd2e83cf93f38ee82f9720e2635fa64"
        hash = "988b125b6727b94ce9a27ea42edc0ce282c5dfeb"
        hash = "0ce760131787803bbef216d0ee9b5eb062633537"
        hash = "20281d16838f707c86b1ff1428a293ed6aec0e97"

        id = "05bb3e0c-69b2-5176-a3eb-e6ba2d72a205"
    strings:
        $sus3 = "'upload'" ascii
        $sus4 = "\"upload\"" ascii
        $sus5 = "\"Upload\"" ascii
        $sus6 = "gif89" ascii
        //$sus13= "<textarea " ascii
        $sus16= "Army" fullword ascii
        $sus17= "error_reporting( 0 )" ascii
        $sus18= "' . '" ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" ascii
        $no_xml2 = "<?xml-stylesheet" ascii
        $no_asp1 = "<%@LANGUAGE" ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ ascii
        $php_new2 = "<?php" ascii
        $php_new3 = "<script language=\"php" ascii

        //strings from private rule capa_php_input
        $inp1 = "php://input" ascii
        $inp2 = /_GET\s?\[/ ascii
        // for passing $_GET to a function
        $inp3 = /\(\s?\$_GET\s?\)/ ascii
        $inp4 = /_POST\s?\[/ ascii
        $inp5 = /\(\s?\$_POST\s?\)/ ascii
        $inp6 = /_REQUEST\s?\[/ ascii
        $inp7 = /\(\s?\$_REQUEST\s?\)/ ascii
        // PHP automatically adds all the request headers into the $_SERVER global array, prefixing each header name by the "HTTP_" string, so e.g. @eval($_SERVER['HTTP_CMD']) will run any code in the HTTP header CMD
        $inp15 = "_SERVER['HTTP_" ascii
        $inp16 = "_SERVER[\"HTTP_" ascii
        $inp17 = /getenv[\t ]{0,20}\([\t ]{0,20}['"]HTTP_/ ascii
        $inp18 = "array_values($_SERVER)" ascii
        $inp19 = /file_get_contents\("https?:\/\// ascii

        //strings from private rule capa_php_write_file
        $php_multi_write1 = "fopen(" ascii
        $php_multi_write2 = "fwrite(" ascii
        $php_write1 = "move_uploaded_file" fullword ascii
        $php_write2 = "copy" fullword ascii

condition:
    any of them
}

rule WEBSHELL_ASP_Writer
{
    meta:
        description = "ASP webshell which only writes an uploaded file to disk"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/03/07"
        modified = "2023-07-05"
        score = 60
        hash = "df6eaba8d643c49c6f38016531c88332e80af33c"
        hash = "83642a926291a499916e8c915dacadd0d5a8b91f"
        hash = "5417fad68a6f7320d227f558bf64657fe3aa9153"
        hash = "97d9f6c411f54b56056a145654cd00abca2ff871"
        hash = "fc44fd7475ee6c0758ace2b17dd41ed7ea75cc73"

        id = "a1310e22-f485-5f06-8f1a-4cf9ae8413a1"
    strings:
        $sus1 = "password" fullword ascii
        $sus2 = "pwd" fullword ascii
        $sus3 = "<asp:TextBox" fullword ascii
        $sus4 = "\"upload\"" ascii
        $sus5 = "\"Upload\"" ascii
        $sus6 = "gif89" ascii
        $sus7 = "\"&\"" ascii
        $sus8 = "authkey" fullword ascii
        $sus9 = "AUTHKEY" fullword ascii
        $sus10= "test.asp" fullword ascii
        $sus11= "cmd.asp" fullword ascii
        $sus12= ".Write(Request." ascii
        $sus13= "<textarea " ascii
        $sus14= "\"unsafe" fullword ascii
        $sus15= "'unsafe" fullword ascii
        $sus16= "Army" fullword ascii

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" ascii
        $tagasp_long10 = "<%@ " ascii
        // <% eval
        $tagasp_long11 = /<% \w/ ascii
        $tagasp_long12 = "<%ex" ascii
        $tagasp_long13 = "<%ev" ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." ascii
        $jsp2 = "=\"javax." ascii
        $jsp3 = "java.lang." ascii
        $jsp4 = "public" fullword ascii
        $jsp5 = "throws" fullword ascii
        $jsp6 = "getValue" fullword ascii
        $jsp7 = "getBytes" fullword ascii

        $perl1 = "PerlScript" fullword ascii


        //strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        $asp_input1 = "request" fullword ascii
        $asp_input2 = "Page_Load" fullword ascii
        //  of Request.Form(
        $asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword ascii
        $asp_xml_http = "Microsoft.XMLHTTP" fullword ascii
        $asp_xml_method1 = "GET" fullword ascii
        $asp_xml_method2 = "POST" fullword ascii
        $asp_xml_method3 = "HEAD" fullword ascii
        // dynamic form
        $asp_form1 = "<form " ascii
        $asp_form2 = "<Form " ascii
        $asp_form3 = "<FORM " ascii
        $asp_asp   = "<asp:" ascii
        $asp_text1 = ".text" ascii
        $asp_text2 = ".Text" ascii

        //strings from private rule capa_asp_write_file
        // $asp_write1 = "ADODB.Stream" ascii # just a string, can be easily obfuscated
        $asp_always_write1 = /\.write/ ascii
        $asp_always_write2 = /\.swrite/ ascii
        //$asp_write_way_one1 = /\.open\b/ ascii
        $asp_write_way_one2 = "SaveToFile" fullword ascii
        $asp_write_way_one3 = "CREAtEtExtFiLE" fullword ascii
        $asp_cr_write1 = "CreateObject(" ascii
        $asp_cr_write2 = "CreateObject (" ascii
        $asp_streamwriter1 = "streamwriter" fullword ascii
        $asp_streamwriter2 = "filestream" fullword ascii

condition:
    any of them
}

rule WEBSHELL_ASP_OBFUSC
{
    meta:
        description = "ASP webshell obfuscated"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/12"
        modified = "2023-07-05"
        hash = "ad597eee256de51ffb36518cd5f0f4aa0f254f27517d28fb7543ae313b15e112"
        hash = "e0d21fdc16e0010b88d0197ebf619faa4aeca65243f545c18e10859469c1805a"
        hash = "54a5620d4ea42e41beac08d8b1240b642dd6fd7c"
        hash = "fc44fd7475ee6c0758ace2b17dd41ed7ea75cc73"
        hash = "be2fedc38fc0c3d1f925310d5156ccf3d80f1432"
        hash = "3175ee00fc66921ebec2e7ece8aa3296d4275cb5"
        hash = "d6b96d844ac395358ee38d4524105d331af42ede"
        hash = "cafc4ede15270ab3f53f007c66e82627a39f4d0f"

        id = "3960b692-9f6f-52c5-b881-6f9e1b3ac555"
    strings:
        $asp_obf1 = "/*-/*-*/" ascii
        $asp_obf2 = "u\"+\"n\"+\"s" ascii
        $asp_obf3 = "\"e\"+\"v" ascii
        $asp_obf4 = "a\"+\"l\"" ascii
        $asp_obf5 = "\"+\"(\"+\"" ascii
        $asp_obf6 = "q\"+\"u\"" ascii
        $asp_obf7 = "\"u\"+\"e" ascii
        $asp_obf8 = "/*//*/" ascii

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" ascii
        $tagasp_long10 = "<%@ " ascii
        // <% eval
        $tagasp_long11 = /<% \w/ ascii
        $tagasp_long12 = "<%ex" ascii
        $tagasp_long13 = "<%ev" ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." ascii
        $jsp2 = "=\"javax." ascii
        $jsp3 = "java.lang." ascii
        $jsp4 = "public" fullword ascii
        $jsp5 = "throws" fullword ascii
        $jsp6 = "getValue" fullword ascii
        $jsp7 = "getBytes" fullword ascii

        $perl1 = "PerlScript" fullword ascii


        //strings from private rule capa_asp_payload
        $asp_payload0  = "eval_r" fullword ascii
        $asp_payload1  = /\beval\s/ ascii
        $asp_payload2  = /\beval\(/ ascii
        $asp_payload3  = /\beval\"\"/ ascii
        // var Fla = {'E':eval};  Fla.E(code)
        $asp_payload4  = /:\s{0,10}eval\b/ ascii
        $asp_payload8  = /\bexecute\s?\(/ ascii
        $asp_payload9  = /\bexecute\s[\w"]/ ascii
        $asp_payload11 = "WSCRIPT.SHELL" fullword ascii
        $asp_payload13 = "ExecuteGlobal" fullword ascii
        $asp_payload14 = "ExecuteStatement" fullword ascii
        $asp_payload15 = "ExecuteStatement" fullword ascii
        $asp_multi_payload_one1 = "CreateObject" fullword ascii
        $asp_multi_payload_one2 = "addcode" fullword ascii
        $asp_multi_payload_one3 = /\.run\b/ ascii
        $asp_multi_payload_two1 = "CreateInstanceFromVirtualPath" fullword ascii
        $asp_multi_payload_two2 = "ProcessRequest" fullword ascii
        $asp_multi_payload_two3 = "BuildManager" fullword ascii
        $asp_multi_payload_three1 = "System.Diagnostics" ascii
        $asp_multi_payload_three2 = "Process" fullword ascii
        $asp_multi_payload_three3 = ".Start" ascii
        // this is about "MSXML2.DOMDocument" but since that's easily obfuscated, lets not search for it
        $asp_multi_payload_four1 = "CreateObject" fullword ascii
        $asp_multi_payload_four2 = "TransformNode" fullword ascii
        $asp_multi_payload_four3 = "loadxml" fullword ascii

        // execute cmd.exe /c with arguments using ProcessStartInfo
        $asp_multi_payload_five1 = "ProcessStartInfo" fullword ascii
        $asp_multi_payload_five2 = ".Start" ascii
        $asp_multi_payload_five3 = ".Filename" ascii
        $asp_multi_payload_five4 = ".Arguments" ascii


        //strings from private rule capa_asp_write_file
        // $asp_write1 = "ADODB.Stream" ascii # just a string, can be easily obfuscated
        $asp_always_write1 = /\.write/ ascii
        $asp_always_write2 = /\.swrite/ ascii
        //$asp_write_way_one1 = /\.open\b/ ascii
        $asp_write_way_one2 = "SaveToFile" fullword ascii
        $asp_write_way_one3 = "CREAtEtExtFiLE" fullword ascii
        $asp_cr_write1 = "CreateObject(" ascii
        $asp_cr_write2 = "CreateObject (" ascii
        $asp_streamwriter1 = "streamwriter" fullword ascii
        $asp_streamwriter2 = "filestream" fullword ascii

        //strings from private rule capa_asp_obfuscation_multi
        // many Chr or few and a loop????
        //$loop1 = "For "
        //$o1 = "chr(" ascii
        //$o2 = "chr (" ascii
        // not excactly a string function but also often used in obfuscation
        $o4 = "\\x8" ascii
        $o5 = "\\x9" ascii
        // just picking some random numbers because they should appear often enough in a long obfuscated blob and it's faster than a regex
        $o6 = "\\61" ascii
        $o7 = "\\44" ascii
        $o8 = "\\112" ascii
        $o9 = "\\120" ascii
        //$o10 = " & \"" ascii
        //$o11 = " += \"" ascii
        // used for e.g. "scr"&"ipt"

        $m_multi_one1 = "Replace(" ascii
        $m_multi_one2 = "Len(" ascii
        $m_multi_one3 = "Mid(" ascii
        $m_multi_one4 = "mid(" ascii
        $m_multi_one5 = ".ToString(" ascii

        /*
        $m_multi_one5 = "InStr(" ascii
        $m_multi_one6 = "Function" ascii

        $m_multi_two1 = "for each" ascii
        $m_multi_two2 = "split(" ascii
        $m_multi_two3 = " & chr(" ascii
        $m_multi_two4 = " & Chr(" ascii
        $m_multi_two5 = " & Chr (" ascii

        $m_multi_three1 = "foreach" fullword ascii
        $m_multi_three2 = "(char" ascii

        $m_multi_four1 = "FromBase64String(" ascii
        $m_multi_four2 = ".Replace(" ascii
        $m_multi_five1 = "String.Join(\"\"," ascii
        $m_multi_five2 = ".Trim(" ascii
        $m_any1 = " & \"2" ascii
        $m_any2 = " += \"2" ascii
        */

        $m_fp1 = "Author: Andre Teixeira - andret@microsoft.com" /* FPs with 0227f4c366c07c45628b02bae6b4ad01 */
        $m_fp2 = "DataBinder.Eval(Container.DataItem" ascii 


        //strings from private rule capa_asp_obfuscation_obviously
        $oo1 = /\w\"&\"\w/ ascii
        $oo2 = "*/\").Replace(\"/*" ascii

condition:
    any of them
}

rule WEBSHELL_ASP_Generic_Eval_On_Input
{
    meta:
        description = "Generic ASP webshell which uses any eval/exec function directly on user input"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "d6b96d844ac395358ee38d4524105d331af42ede"
        hash = "9be2088d5c3bfad9e8dfa2d7d7ba7834030c7407"
        hash = "a1df4cfb978567c4d1c353e988915c25c19a0e4a"
        hash = "069ea990d32fc980939fffdf1aed77384bf7806bc57c0a7faaff33bd1a3447f6"

        id = "0904cefb-6e0f-5e5f-9986-cf83d409ce46"
    strings:
        $payload_and_input0 = /\beval_r\s{0,20}\(Request\(/ ascii
        $payload_and_input1 = /\beval[\s\(]{1,20}request[.\(\[]/ ascii
        $payload_and_input2 = /\bexecute[\s\(]{1,20}request\(/ ascii
        $payload_and_input4 = /\bExecuteGlobal\s{1,20}request\(/ ascii

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" ascii
        $tagasp_long10 = "<%@ " ascii
        // <% eval
        $tagasp_long11 = /<% \w/ ascii
        $tagasp_long12 = "<%ex" ascii
        $tagasp_long13 = "<%ev" ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." ascii
        $jsp2 = "=\"javax." ascii
        $jsp3 = "java.lang." ascii
        $jsp4 = "public" fullword ascii
        $jsp5 = "throws" fullword ascii
        $jsp6 = "getValue" fullword ascii
        $jsp7 = "getBytes" fullword ascii

        $perl1 = "PerlScript" fullword ascii


condition:
    any of them
}

rule WEBSHELL_ASP_Nano
{
    meta:
        description = "Generic ASP webshell which uses any eval/exec function"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/13"
        modified = "2023-04-05"
        hash = "3b7910a499c603715b083ddb6f881c1a0a3a924d"
        hash = "990e3f129b8ba409a819705276f8fa845b95dad0"
        hash = "22345e956bce23304f5e8e356c423cee60b0912c"
        hash = "c84a6098fbd89bd085526b220d0a3f9ab505bcba"
        hash = "b977c0ad20dc738b5dacda51ec8da718301a75d7"
        hash = "c69df00b57fd127c7d4e0e2a40d2f6c3056e0af8bfb1925938060b7e0d8c630f"
        hash = "f3b39a5da1cdde9acde077208e8e5b27feb973514dab7f262c7c6b2f8f11eaa7"
        hash = "0e9d92807d990144c637d8b081a6a90a74f15c7337522874cf6317092ea2d7c1"
        hash = "ebbc485e778f8e559ef9c66f55bb01dc4f5dcce9c31ccdd150e2c702c4b5d9e1"
        hash = "44b4068bfbbb8961e16bae238ad23d181ac9c8e4fcb4b09a66bbcd934d2d39ee"
        hash = "c5a4e188780b5513f34824904d56bf6e364979af6782417ccc5e5a8a70b4a95a"
        hash = "41a3cc668517ec207c990078bccfc877e239b12a7ff2abe55ff68352f76e819c"
        hash = "2faad5944142395794e5e6b90a34a6204412161f45e130aeb9c00eff764f65fc"
        hash = "d0c5e641120b8ea70a363529843d9f393074c54af87913b3ab635189fb0c84cb"
        hash = "28cfcfe28419a399c606bf96505bc68d6fe05624dba18306993f9fe0d398fbe1"

        id = "5f2f24c2-159d-51e1-80d9-11eeb77e8760"
    strings:
        $susasp1  = "/*-/*-*/"
        $susasp2  = "(\"%1"
        $susasp3  = /[Cc]hr\([Ss]tr\(/
        $susasp4  = "cmd.exe"
        $susasp5  = "cmd /c"
        $susasp7  = "FromBase64String"
        // Request and request in b64:
        $susasp8  = "UmVxdWVzdC"
        $susasp9  = "cmVxdWVzdA"
        $susasp10 = "/*//*/"
        $susasp11 = "(\"/*/\""
        $susasp12 = "eval(eval("
        $fp1      = "eval a"
        $fp2      = "'Eval'"
        $fp3      = "Eval(\""

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" ascii
        $tagasp_long10 = "<%@ " ascii
        // <% eval
        $tagasp_long11 = /<% \w/ ascii
        $tagasp_long12 = "<%ex" ascii
        $tagasp_long13 = "<%ev" ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." ascii
        $jsp2 = "=\"javax." ascii
        $jsp3 = "java.lang." ascii
        $jsp4 = "public" fullword ascii
        $jsp5 = "throws" fullword ascii
        $jsp6 = "getValue" fullword ascii
        $jsp7 = "getBytes" fullword ascii

        $perl1 = "PerlScript" fullword ascii


        //strings from private rule capa_asp_payload
        $asp_payload0  = "eval_r" fullword ascii
        $asp_payload1  = /\beval\s/ ascii
        $asp_payload2  = /\beval\(/ ascii
        $asp_payload3  = /\beval\"\"/ ascii
        // var Fla = {'E':eval};  Fla.E(code)
        $asp_payload4  = /:\s{0,10}eval\b/ ascii
        $asp_payload8  = /\bexecute\s?\(/ ascii
        $asp_payload9  = /\bexecute\s[\w"]/ ascii
        $asp_payload11 = "WSCRIPT.SHELL" fullword ascii
        $asp_payload13 = "ExecuteGlobal" fullword ascii
        $asp_payload14 = "ExecuteStatement" fullword ascii
        $asp_payload15 = "ExecuteStatement" fullword ascii
        $asp_multi_payload_one1 = "CreateObject" fullword ascii
        $asp_multi_payload_one2 = "addcode" fullword ascii
        $asp_multi_payload_one3 = /\.run\b/ ascii
        $asp_multi_payload_two1 = "CreateInstanceFromVirtualPath" fullword ascii
        $asp_multi_payload_two2 = "ProcessRequest" fullword ascii
        $asp_multi_payload_two3 = "BuildManager" fullword ascii
        $asp_multi_payload_three1 = "System.Diagnostics" ascii
        $asp_multi_payload_three2 = "Process" fullword ascii
        $asp_multi_payload_three3 = ".Start" ascii
        // this is about "MSXML2.DOMDocument" but since that's easily obfuscated, lets not search for it
        $asp_multi_payload_four1 = "CreateObject" fullword ascii
        $asp_multi_payload_four2 = "TransformNode" fullword ascii
        $asp_multi_payload_four3 = "loadxml" fullword ascii

        // execute cmd.exe /c with arguments using ProcessStartInfo
        $asp_multi_payload_five1 = "ProcessStartInfo" fullword ascii
        $asp_multi_payload_five2 = ".Start" ascii
        $asp_multi_payload_five3 = ".Filename" ascii
        $asp_multi_payload_five4 = ".Arguments" ascii


        //strings from private rule capa_asp_write_file
        // $asp_write1 = "ADODB.Stream" ascii # just a string, can be easily obfuscated
        $asp_always_write1 = /\.write/ ascii
        $asp_always_write2 = /\.swrite/ ascii
        //$asp_write_way_one1 = /\.open\b/ ascii
        $asp_write_way_one2 = "SaveToFile" fullword ascii
        $asp_write_way_one3 = "CREAtEtExtFiLE" fullword ascii
        $asp_cr_write1 = "CreateObject(" ascii
        $asp_cr_write2 = "CreateObject (" ascii
        $asp_streamwriter1 = "streamwriter" fullword ascii
        $asp_streamwriter2 = "filestream" fullword ascii

condition:
    any of them
}

rule WEBSHELL_ASP_Encoded
{
    meta:
        description = "Webshell in VBscript or JScript encoded using *.Encode plus a suspicious string"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/03/14"
        modified = "2023-07-05"
        hash = "1bc7327f9d3dbff488e5b0b69a1b39dcb99b3399"
        hash = "9885ee1952b5ad9f84176c9570ad4f0e32461c92"
        hash = "27a020c5bc0dbabe889f436271df129627b02196"
        hash = "f41f8c82b155c3110fc1325e82b9ee92b741028b"
        hash = "af40f4c36e3723236c59dc02f28a3efb047d67dd"

        id = "67c0e1f6-6da5-569c-ab61-8b8607429471"
    strings:
        $encoded1 = "VBScript.Encode" ascii
        $encoded2 = "JScript.Encode" ascii
        $data1 = "#@~^" ascii
        $sus1 = "shell" ascii
        $sus2 = "cmd" fullword ascii
        $sus3 = "password" fullword ascii
        $sus4 = "UserPass" fullword ascii

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" ascii
        $tagasp_long10 = "<%@ " ascii
        // <% eval
        $tagasp_long11 = /<% \w/ ascii
        $tagasp_long12 = "<%ex" ascii
        $tagasp_long13 = "<%ev" ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." ascii
        $jsp2 = "=\"javax." ascii
        $jsp3 = "java.lang." ascii
        $jsp4 = "public" fullword ascii
        $jsp5 = "throws" fullword ascii
        $jsp6 = "getValue" fullword ascii
        $jsp7 = "getBytes" fullword ascii

        $perl1 = "PerlScript" fullword ascii


condition:
    any of them
}

rule WEBSHELL_ASP_Encoded_AspCoding
{
    meta:
        description = "ASP Webshell encoded using ASPEncodeDLL.AspCoding"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/03/14"
        modified = "2023-07-05"
        score = 60
        hash = "7cfd184ab099c4d60b13457140493b49c8ba61ee"
        hash = "f5095345ee085318235c11ae5869ae564d636a5342868d0935de7582ba3c7d7a"

        id = "788a8dae-bcb8-547c-ba17-e1f14bc28f34"
    strings:
        $encoded1 = "ASPEncodeDLL" fullword ascii
        $encoded2 = ".Runt" ascii
        $encoded3 = "Request" fullword ascii
        $encoded4 = "Response" fullword ascii
        $data1 = "AspCoding.EnCode" ascii
        //$sus1 = "shell" ascii
        //$sus2 = "cmd" fullword ascii
        //$sus3 = "password" fullword ascii
        //$sus4 = "UserPass" fullword ascii

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" ascii
        $tagasp_long10 = "<%@ " ascii
        // <% eval
        $tagasp_long11 = /<% \w/ ascii
        $tagasp_long12 = "<%ex" ascii
        $tagasp_long13 = "<%ev" ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." ascii
        $jsp2 = "=\"javax." ascii
        $jsp3 = "java.lang." ascii
        $jsp4 = "public" fullword ascii
        $jsp5 = "throws" fullword ascii
        $jsp6 = "getValue" fullword ascii
        $jsp7 = "getBytes" fullword ascii

        $perl1 = "PerlScript" fullword ascii


condition:
    any of them
}

rule WEBSHELL_ASP_By_String
{
    meta:
        description = "Known ASP Webshells which contain unique strings, lousy rule for low hanging fruits. Most are catched by other rules in here but maybe these catch different versions."
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021-01-13"
        modified = "2023-04-05"
        hash = "f72252b13d7ded46f0a206f63a1c19a66449f216"
        hash = "bd75ac9a1d1f6bcb9a2c82b13ea28c0238360b3a7be909b2ed19d3c96e519d3d"
        hash = "56a54fe1f8023455800fd0740037d806709ffb9ece1eb9e7486ad3c3e3608d45"
        hash = "4ef5d8b51f13b36ce7047e373159d7bb42ca6c9da30fad22e083ab19364c9985"
        hash = "e90c3c270a44575c68d269b6cf78de14222f2cbc5fdfb07b9995eb567d906220"
        hash = "8a38835f179e71111663b19baade78cc3c9e1f6fcc87eb35009cbd09393cbc53"
        hash = "f2883e9461393b33feed4139c0fc10fcc72ff92924249eb7be83cb5b76f0f4ee"
        hash = "10cca59c7112dfb1c9104d352e0504f842efd4e05b228b6f34c2d4e13ffd0eb6"
        hash = "ed179e5d4d365b0332e9ffca83f66ee0afe1f1b5ac3c656ccd08179170a4d9f7"
        hash = "ce3273e98e478a7e95fccce0a3d3e8135c234a46f305867f2deacd4f0efa7338"
        hash = "65543373b8bd7656478fdf9ceeacb8490ff8976b1fefc754cd35c89940225bcf"
        hash = "de173ea8dcef777368089504a4af0804864295b75e51794038a6d70f2bcfc6f5"


        id = "4705b28b-2ffa-53d1-b727-1a9fc2a7dd69"
    strings:
        // reversed
        $asp_string1  = "tseuqer lave" ascii
        $asp_string2  = ":eval request(" ascii
        $asp_string3  = ":eval request(" ascii
        $asp_string4  = "SItEuRl=\"http://www.zjjv.com\"" ascii
        $asp_string5  = "ServerVariables(\"HTTP_HOST\"),\"gov.cn\"" ascii
        // e+k-v+k-a+k-l
        // e+x-v+x-a+x-l
        $asp_string6  = /e\+.-v\+.-a\+.-l/ ascii
        $asp_string7  = "r+x-e+x-q+x-u" ascii
        $asp_string8  = "add6bb58e139be10" fullword ascii
        $asp_string9  = "WebAdmin2Y.x.y(\"" ascii
        $asp_string10 = "<%if (Request.Files.Count!=0) { Request.Files[0].SaveAs(Server.MapPath(Request[" ascii
        $asp_string11 = "<% If Request.Files.Count <> 0 Then Request.Files(0).SaveAs(Server.MapPath(Request(" ascii
        // Request.Item["
        $asp_string12 = "UmVxdWVzdC5JdGVtWyJ" ascii

        // eval( in utf7 in  all 3 versions
        $asp_string13 = "UAdgBhAGwAKA" ascii
        $asp_string14 = "lAHYAYQBsACgA" ascii
        $asp_string15 = "ZQB2AGEAbAAoA" ascii
        // request in utf7 in  all 3 versions
        $asp_string16 = "IAZQBxAHUAZQBzAHQAKA" ascii
        $asp_string17 = "yAGUAcQB1AGUAcwB0ACgA" ascii
        $asp_string18 = "cgBlAHEAdQBlAHMAdAAoA" ascii

        $asp_string19 = "\"ev\"&\"al" ascii
        $asp_string20 = "\"Sc\"&\"ri\"&\"p" ascii
        $asp_string21 = "C\"&\"ont\"&\"" ascii
        $asp_string22 = "\"vb\"&\"sc" ascii
        $asp_string23 = "\"A\"&\"do\"&\"d" ascii
        $asp_string24 = "St\"&\"re\"&\"am\"" ascii
        $asp_string25 = "*/eval(" ascii
        $asp_string26 = "\"e\"&\"v\"&\"a\"&\"l"
        $asp_string27 = "<%eval\"\"&(\"" ascii
        $asp_string28 = "6877656D2B736972786677752B237E232C2A" ascii
        $asp_string29 = "ws\"&\"cript.shell" ascii
        $asp_string30 = "SerVer.CreAtEoBjECT(\"ADODB.Stream\")" ascii
        $asp_string31 = "ASPShell - web based shell" ascii
        $asp_string32 = "<++ CmdAsp.asp ++>" ascii
        $asp_string33 = "\"scr\"&\"ipt\"" ascii
        $asp_string34 = "Regex regImg = new Regex(\"[a-z|A-Z]{1}:\\\\\\\\[a-z|A-Z| |0-9|\\u4e00-\\u9fa5|\\\\~|\\\\\\\\|_|{|}|\\\\.]*\");" ascii
        $asp_string35 = "\"she\"&\"ll." ascii
        $asp_string36 = "LH\"&\"TTP" ascii
        $asp_string37 = "<title>Web Sniffer</title>" ascii
        $asp_string38 = "<title>WebSniff" ascii
        $asp_string39 = "cript\"&\"ing" ascii
        $asp_string40 = "tcejbOmetsySeliF.gnitpircS" ascii
        $asp_string41 = "tcejbOetaerC.revreS" ascii
        $asp_string42 = "This file is part of A Black Path Toward The Sun (\"ABPTTS\")" ascii
        $asp_string43 = "if ((Request.Headers[headerNameKey] != null) && (Request.Headers[headerNameKey].Trim() == headerValueKey.Trim()))" ascii
        $asp_string44 = "if (request.getHeader(headerNameKey).toString().trim().equals(headerValueKey.trim()))" ascii
        $asp_string45 = "Response.Write(Server.HtmlEncode(ExcutemeuCmd(txtArg.Text)));" ascii
        $asp_string46 = "\"c\" + \"m\" + \"d\"" ascii
        $asp_string47 = "\".\"+\"e\"+\"x\"+\"e\"" ascii
        $asp_string48 = "Tas9er" fullword ascii
        $asp_string49 = "<%@ Page Language=\"\\u" ascii
        $asp_string50 = "BinaryRead(\\u" ascii
        $asp_string51 = "Request.\\u" ascii
        $asp_string52 = "System.Buffer.\\u" ascii
        $asp_string53 = "System.Net.\\u" ascii
        $asp_string54 = ".\\u0052\\u0065\\u0066\\u006c\\u0065\\u0063\\u0074\\u0069\\u006f\\u006e\"" ascii
        $asp_string55 = "\\u0041\\u0073\\u0073\\u0065\\u006d\\u0062\\u006c\\u0079.\\u004c\\u006f\\u0061\\u0064" ascii
        $asp_string56 = "\\U00000052\\U00000065\\U00000071\\U00000075\\U00000065\\U00000073\\U00000074[\"" ascii
        $asp_string57 = "*/\\U0000" ascii
        $asp_string58 = "\\U0000FFFA" ascii
        $asp_string59 = "\"e45e329feb5d925b\"" ascii
        $asp_string60 = ">POWER!shelled<" ascii
        $asp_string61 = "@requires xhEditor" ascii


        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" ascii
        $tagasp_long10 = "<%@ " ascii
        // <% eval
        $tagasp_long11 = /<% \w/ ascii
        $tagasp_long12 = "<%ex" ascii
        $tagasp_long13 = "<%ev" ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." ascii
        $jsp2 = "=\"javax." ascii
        $jsp3 = "java.lang." ascii
        $jsp4 = "public" fullword ascii
        $jsp5 = "throws" fullword ascii
        $jsp6 = "getValue" fullword ascii
        $jsp7 = "getBytes" fullword ascii

        $perl1 = "PerlScript" fullword ascii


condition:
    any of them
}

rule WEBSHELL_ASP_Sniffer
{
    meta:
        description = "ASP webshell which can sniff local traffic"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/03/14"
        modified = "2023-07-05"
        hash = "1206c22de8d51055a5e3841b4542fb13aa0f97dd"
        hash = "60d131af1ed23810dbc78f85ee32ffd863f8f0f4"
        hash = "c3bc4ab8076ef184c526eb7f16e08d41b4cec97e"
        hash = "ed5938c04f61795834751d44a383f8ca0ceac833"

        id = "b5704c19-fce1-5210-8185-4839c1c5a344"
    strings:
        $sniff1 = "Socket(" ascii
        $sniff2 = ".Bind(" ascii
        $sniff3 = ".SetSocketOption(" ascii
        $sniff4 = ".IOControl(" ascii
        $sniff5 = "PacketCaptureWriter" fullword ascii

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" ascii
        $tagasp_long10 = "<%@ " ascii
        // <% eval
        $tagasp_long11 = /<% \w/ ascii
        $tagasp_long12 = "<%ex" ascii
        $tagasp_long13 = "<%ev" ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." ascii
        $jsp2 = "=\"javax." ascii
        $jsp3 = "java.lang." ascii
        $jsp4 = "public" fullword ascii
        $jsp5 = "throws" fullword ascii
        $jsp6 = "getValue" fullword ascii
        $jsp7 = "getBytes" fullword ascii

        $perl1 = "PerlScript" fullword ascii


        //strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        $asp_input1 = "request" fullword ascii
        $asp_input2 = "Page_Load" fullword ascii
        //  of Request.Form(
        $asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword ascii
        $asp_xml_http = "Microsoft.XMLHTTP" fullword ascii
        $asp_xml_method1 = "GET" fullword ascii
        $asp_xml_method2 = "POST" fullword ascii
        $asp_xml_method3 = "HEAD" fullword ascii
        // dynamic form
        $asp_form1 = "<form " ascii
        $asp_form2 = "<Form " ascii
        $asp_form3 = "<FORM " ascii
        $asp_asp   = "<asp:" ascii
        $asp_text1 = ".text" ascii
        $asp_text2 = ".Text" ascii

condition:
    any of them
}

rule WEBSHELL_ASP_Generic_Tiny
{
    meta:
        description = "Generic tiny ASP webshell which uses any eval/exec function indirectly on user input or writes a file"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2025-08-18"
        hash = "990e3f129b8ba409a819705276f8fa845b95dad0"
        hash = "52ce724580e533da983856c4ebe634336f5fd13a"
        hash = "0864f040a37c3e1cef0213df273870ed6a61e4bc"
        hash = "b184dc97b19485f734e3057e67007a16d47b2a62"

        id = "0904cefb-6e0f-5e5f-9986-cf83d409ce46"
    strings:
        $fp1 = "net.rim.application.ipproxyservice.AdminCommand.execute"

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" ascii
        $tagasp_long10 = "<%@ " ascii
        // <% eval
        $tagasp_long11 = /<% \w/ ascii
        $tagasp_long12 = "<%ex" ascii
        $tagasp_long13 = "<%ev" ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." ascii
        $jsp2 = "=\"javax." ascii
        $jsp3 = "java.lang." ascii
        $jsp4 = "public" fullword ascii
        $jsp5 = "throws" fullword ascii
        $jsp6 = "getValue" fullword ascii
        $jsp7 = "getBytes" fullword ascii

        $perl1 = "PerlScript" fullword ascii


        //strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        $asp_input1 = "request" fullword ascii
        $asp_input2 = "Page_Load" fullword ascii
        //  of Request.Form(
        $asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword ascii
        $asp_xml_http = "Microsoft.XMLHTTP" fullword ascii
        $asp_xml_method1 = "GET" fullword ascii
        $asp_xml_method2 = "POST" fullword ascii
        $asp_xml_method3 = "HEAD" fullword ascii
        // dynamic form
        $asp_form1 = "<form " ascii
        $asp_form2 = "<Form " ascii
        $asp_form3 = "<FORM " ascii
        $asp_asp   = "<asp:" ascii
        $asp_text1 = ".text" ascii
        $asp_text2 = ".Text" ascii

        //strings from private rule capa_bin_files
        $dex1 = "dex\n0"
        $dex2 = "dey\n0"
        $pack  = { 50 41 43 4b 00 00 00 02 00 }

        //strings from private rule capa_asp_payload
        $asp_payload0  = "eval_r" fullword ascii
        $asp_payload1  = /\beval\s/ ascii
        $asp_payload2  = /\beval\(/ ascii
        $asp_payload3  = /\beval\"\"/ ascii
        // var Fla = {'E':eval};  Fla.E(code)
        $asp_payload4  = /:\s{0,10}eval\b/ ascii
        $asp_payload8  = /\bexecute\s?\(/ ascii
        $asp_payload9  = /\bexecute\s[\w"]/ ascii
        $asp_payload11 = "WSCRIPT.SHELL" fullword ascii
        $asp_payload13 = "ExecuteGlobal" fullword ascii
        $asp_payload14 = "ExecuteStatement" fullword ascii
        $asp_payload15 = "ExecuteStatement" fullword ascii
        $asp_multi_payload_one1 = "CreateObject" fullword ascii
        $asp_multi_payload_one2 = "addcode" fullword ascii
        $asp_multi_payload_one3 = /\.run\b/ ascii
        $asp_multi_payload_two1 = "CreateInstanceFromVirtualPath" fullword ascii
        $asp_multi_payload_two2 = "ProcessRequest" fullword ascii
        $asp_multi_payload_two3 = "BuildManager" fullword ascii
        $asp_multi_payload_three1 = "System.Diagnostics" ascii
        $asp_multi_payload_three2 = "Process" fullword ascii
        $asp_multi_payload_three3 = ".Start" ascii
        // this is about "MSXML2.DOMDocument" but since that's easily obfuscated, lets not search for it
        $asp_multi_payload_four1 = "CreateObject" fullword ascii
        $asp_multi_payload_four2 = "TransformNode" fullword ascii
        $asp_multi_payload_four3 = "loadxml" fullword ascii

        // execute cmd.exe /c with arguments using ProcessStartInfo
        $asp_multi_payload_five1 = "ProcessStartInfo" fullword ascii
        $asp_multi_payload_five2 = ".Start" ascii
        $asp_multi_payload_five3 = ".Filename" ascii
        $asp_multi_payload_five4 = ".Arguments" ascii


        //strings from private rule capa_asp_write_file
        // $asp_write1 = "ADODB.Stream" ascii # just a string, can be easily obfuscated
        $asp_always_write1 = /\.write/ ascii
        $asp_always_write2 = /\.swrite/ ascii
        //$asp_write_way_one1 = /\.open\b/ ascii
        $asp_write_way_one2 = "SaveToFile" fullword ascii
        $asp_write_way_one3 = "CREAtEtExtFiLE" fullword ascii
        $asp_cr_write1 = "CreateObject(" ascii
        $asp_cr_write2 = "CreateObject (" ascii
        $asp_streamwriter1 = "streamwriter" fullword ascii
        $asp_streamwriter2 = "filestream" fullword ascii

condition:
    any of them
}

rule WEBSHELL_ASP_Generic {
    meta:
        description = "Generic ASP webshell which uses any eval/exec function indirectly on user input or writes a file"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021-03-07"
        modified = "2025-08-18"
        score = 60
        hash = "a8c63c418609c1c291b3e731ca85ded4b3e0fba83f3489c21a3199173b176a75"
        hash = "4cf6fbad0411b7d33e38075f5e00d4c8ae9ce2f6f53967729974d004a183b25c"
        hash = "a91320483df0178eb3cafea830c1bd94585fc896"
        hash = "f3398832f697e3db91c3da71a8e775ebf66c7e73"
        id = "0904cefb-6e0f-5e5f-9986-cf83d409ce46"
    strings:
        $asp_much_sus7  = "Web Shell" 
        $asp_much_sus8  = "WebShell" 
        $asp_much_sus3  = "hidded shell"
        $asp_much_sus4  = "WScript.Shell.1" 
        $asp_much_sus5  = "AspExec"
        $asp_much_sus14 = "\\pcAnywhere\\" 
        $asp_much_sus15 = "antivirus" 
        $asp_much_sus16 = "McAfee" 
        $asp_much_sus17 = "nishang"
        $asp_much_sus18 = "\"unsafe" fullword ascii
        $asp_much_sus19 = "'unsafe" fullword ascii
        $asp_much_sus28 = "exploit" fullword ascii
        $asp_much_sus30 = "TVqQAAMAAA" ascii
        $asp_much_sus31 = "HACKED" fullword ascii
        $asp_much_sus32 = "hacked" fullword ascii
        $asp_much_sus33 = "hacker" ascii
        $asp_much_sus34 = "grayhat" ascii
        $asp_much_sus35 = "Microsoft FrontPage" ascii
        $asp_much_sus36 = "Rootkit" ascii
        $asp_much_sus37 = "rootkit" ascii
        $asp_much_sus38 = "/*-/*-*/" ascii
        $asp_much_sus39 = "u\"+\"n\"+\"s" ascii
        $asp_much_sus40 = "\"e\"+\"v" ascii
        $asp_much_sus41 = "a\"+\"l\"" ascii
        $asp_much_sus42 = "\"+\"(\"+\"" ascii
        $asp_much_sus43 = "q\"+\"u\"" ascii
        $asp_much_sus44 = "\"u\"+\"e" ascii
        $asp_much_sus45 = "/*//*/" ascii
        $asp_much_sus46 = "(\"/*/\"" ascii
        $asp_much_sus47 = "eval(eval(" ascii
        $asp_much_sus48 = "Shell.Users" ascii
        $asp_much_sus49 = "PasswordType=Regular" ascii
        $asp_much_sus50 = "-Expire=0" ascii
        $asp_much_sus51 = "sh\"&\"el" ascii

        $asp_gen_sus1  = /:\s{0,20}eval}/ ascii
        $asp_gen_sus2  = /\.replace\(\/\w\/g/ ascii
        $asp_gen_sus6  = "self.delete"
        $asp_gen_sus9  = "\"cmd /c"
        $asp_gen_sus10 = "\"cmd\""
        $asp_gen_sus11 = "\"cmd.exe"
        $asp_gen_sus12 = "%comspec%" ascii
        $asp_gen_sus13 = "%COMSPEC%" ascii
        //TODO:$asp_gen_sus12 = ".UserName"
        $asp_gen_sus18 = "Hklm.GetValueNames();" 
        // bonus string for proxylogon exploiting webshells
        $asp_gen_sus19 = "http://schemas.microsoft.com/exchange/" ascii
        $asp_gen_sus21 = "\"upload\"" ascii
        $asp_gen_sus22 = "\"Upload\"" ascii
        $asp_gen_sus25 = "shell_" ascii
        //$asp_gen_sus26 = "password" fullword ascii
        //$asp_gen_sus27 = "passw" fullword ascii
        // own  or base 32 func
        $asp_gen_sus29 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" fullword ascii
        $asp_gen_sus30 = "abcdefghijklmnopqrstuvwxyz234567" fullword ascii
        $asp_gen_sus31 = "serv-u" ascii
        $asp_gen_sus32 = "Serv-u" ascii
        $asp_gen_sus33 = "Army" fullword ascii

        $asp_slightly_sus1 = "<pre>" ascii
        $asp_slightly_sus2 = "<PRE>" ascii


        // "e"+"x"+"e"
        $asp_gen_obf1 = "\"+\"" ascii

        $fp1 = "DataBinder.Eval"
        $fp2 = "B2BTools"
        $fp3 = "<b>Failed to execute cache update. See the log file for more information" ascii
        $fp4 = "Microsoft. All rights reserved."
        $fp5 = "\"unsafe\"," ascii

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" ascii
        $tagasp_long10 = "<%@ " ascii
        // <% eval
        $tagasp_long11 = /<% \w/ ascii
        $tagasp_long12 = "<%ex" ascii
        $tagasp_long13 = "<%ev" ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." ascii
        $jsp2 = "=\"javax." ascii
        $jsp3 = "java.lang." ascii
        $jsp4 = "public" fullword ascii
        $jsp5 = "throws" fullword ascii
        $jsp6 = "getValue" fullword ascii
        $jsp7 = "getBytes" fullword ascii

        $perl1 = "PerlScript" fullword ascii


        //strings from private rule capa_bin_files
        $dex1 = "dex\n0"
        $dex2 = "dey\n0"
        $pack  = { 50 41 43 4b 00 00 00 02 00 }

        //strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        $asp_input1 = "request" fullword ascii
        $asp_input2 = "Page_Load" fullword ascii
        //  of Request.Form(
        $asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword ascii
        $asp_xml_http = "Microsoft.XMLHTTP" fullword ascii
        $asp_xml_method1 = "GET" fullword ascii
        $asp_xml_method2 = "POST" fullword ascii
        $asp_xml_method3 = "HEAD" fullword ascii
        // dynamic form
        $asp_form1 = "<form " ascii
        $asp_form2 = "<Form " ascii
        $asp_form3 = "<FORM " ascii
        $asp_asp   = "<asp:" ascii
        $asp_text1 = ".text" ascii
        $asp_text2 = ".Text" ascii

        //strings from private rule capa_asp_payload
        $asp_payload0  = "eval_r" fullword ascii
        $asp_payload1  = /\beval\s/ ascii
        $asp_payload2  = /\beval\(/ ascii
        $asp_payload3  = /\beval\"\"/ ascii
        // var Fla = {'E':eval};  Fla.E(code)
        $asp_payload4  = /:\s{0,10}eval\b/ ascii
        $asp_payload8  = /\bexecute\s?\(/ ascii
        $asp_payload9  = /\bexecute\s[\w"]/ ascii
        $asp_payload11 = "WSCRIPT.SHELL" fullword ascii
        $asp_payload13 = "ExecuteGlobal" fullword ascii
        $asp_payload14 = "ExecuteStatement" fullword ascii
        $asp_payload15 = "ExecuteStatement" fullword ascii
        $asp_multi_payload_one1 = "CreateObject" fullword ascii
        $asp_multi_payload_one2 = "addcode" fullword ascii
        $asp_multi_payload_one3 = /\.run\b/ ascii
        $asp_multi_payload_two1 = "CreateInstanceFromVirtualPath" fullword ascii
        $asp_multi_payload_two2 = "ProcessRequest" fullword ascii
        $asp_multi_payload_two3 = "BuildManager" fullword ascii
        $asp_multi_payload_three1 = "System.Diagnostics" ascii
        $asp_multi_payload_three2 = "Process" fullword ascii
        $asp_multi_payload_three3 = "Start" fullword ascii
        // this is about "MSXML2.DOMDocument" but since that's easily obfuscated, lets not search for it
        $asp_multi_payload_four1 = "CreateObject" fullword ascii
        $asp_multi_payload_four2 = "TransformNode" fullword ascii
        $asp_multi_payload_four3 = "loadxml" fullword ascii

        // execute cmd.exe /c with arguments using ProcessStartInfo
        $asp_multi_payload_five1 = "ProcessStartInfo" fullword ascii
        $asp_multi_payload_five2 = ".Start" ascii
        $asp_multi_payload_five3 = ".Filename" ascii
        $asp_multi_payload_five4 = ".Arguments" ascii


        //strings from private rule capa_asp_write_file
        // $asp_write1 = "ADODB.Stream" ascii # just a string, can be easily obfuscated
        $asp_always_write1 = /\.write/ ascii
        $asp_always_write2 = /\.swrite/ ascii
        //$asp_write_way_one1 = /\.open\b/ ascii
        $asp_write_way_one2 = "SaveToFile" fullword ascii
        $asp_write_way_one3 = "CREAtEtExtFiLE" fullword ascii
        $asp_cr_write1 = "CreateObject(" ascii
        $asp_cr_write2 = "CreateObject (" ascii
        $asp_streamwriter1 = "streamwriter" fullword ascii
        $asp_streamwriter2 = "filestream" fullword ascii

        //strings from private rule capa_asp_classid
        $tagasp_capa_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" ascii
        $tagasp_capa_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" ascii
        $tagasp_capa_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" ascii
        $tagasp_capa_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" ascii
        $tagasp_capa_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" ascii

condition:
    any of them
}

rule WEBSHELL_ASP_Generic_Registry_Reader
{
    meta:
        description = "Generic ASP webshell which reads the registry (might look for passwords, license keys, database settings, general recon, ..."
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/03/14"
        modified = "2023-07-05"
        score = 50
        hash = "4d53416398a89aef3a39f63338a7c1bf2d3fcda4"
        hash = "f85cf490d7eb4484b415bea08b7e24742704bdda"
        hash = "898ebfa1757dcbbecb2afcdab1560d72ae6940de"

        id = "02d6f95f-1801-5fb0-8ab8-92176cf2fdd7"
    strings:
        /* $asp_reg1  = "Registry" fullword ascii */ /* too many matches issues */
        $asp_reg2  = "LocalMachine" fullword ascii
        $asp_reg3  = "ClassesRoot" fullword ascii
        $asp_reg4  = "CurrentUser" fullword ascii
        $asp_reg5  = "Users" fullword ascii
        $asp_reg6  = "CurrentConfig" fullword ascii
        $asp_reg7  = "Microsoft.Win32" fullword ascii
        $asp_reg8  = "OpenSubKey" fullword ascii

        $sus1 = "shell" fullword ascii
        $sus2 = "cmd.exe" fullword ascii
        $sus3 = "<form " ascii
        $sus4 = "<table " ascii
        $sus5 = "System.Security.SecurityException" ascii

        $fp1 = "Avira Operations GmbH" ascii 

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" ascii
        $tagasp_long10 = "<%@ " ascii
        // <% eval
        $tagasp_long11 = /<% \w/ ascii
        $tagasp_long12 = "<%ex" ascii
        $tagasp_long13 = "<%ev" ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." ascii
        $jsp2 = "=\"javax." ascii
        $jsp3 = "java.lang." ascii
        $jsp4 = "public" fullword ascii
        $jsp5 = "throws" fullword ascii
        $jsp6 = "getValue" fullword ascii
        $jsp7 = "getBytes" fullword ascii

        $perl1 = "PerlScript" fullword ascii


        //strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        $asp_input1 = "request" fullword ascii
        $asp_input2 = "Page_Load" fullword ascii
        //  of Request.Form(
        $asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword ascii
        $asp_xml_http = "Microsoft.XMLHTTP" fullword ascii
        $asp_xml_method1 = "GET" fullword ascii
        $asp_xml_method2 = "POST" fullword ascii
        $asp_xml_method3 = "HEAD" fullword ascii
        // dynamic form
        $asp_form1 = "<form " ascii
        $asp_form2 = "<Form " ascii
        $asp_form3 = "<FORM " ascii
        $asp_asp   = "<asp:" ascii
        $asp_text1 = ".text" ascii
        $asp_text2 = ".Text" ascii

condition:
    any of them
}

rule WEBSHELL_ASPX_Regeorg_CSHARP
{
    meta:
        description = "Webshell regeorg aspx c# version"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        reference = "https://github.com/sensepost/reGeorg"
        hash = "c1f43b7cf46ba12cfc1357b17e4f5af408740af7ae70572c9cf988ac50260ce1"
        author = "Arnim Rupp (https://github.com/ruppde)"
        score = 75
        date = "2021/01/11"
        modified = "2023-07-05"
        hash = "479c1e1f1c263abe339de8be99806c733da4e8c1"
        hash = "38a1f1fc4e30c0b4ad6e7f0e1df5a92a7d05020b"
        hash = "e54f1a3eab740201feda235835fc0aa2e0c44ba9"
        hash = "aea0999c6e5952ec04bf9ee717469250cddf8a6f"

        id = "0a53d368-5f1b-55b7-b08f-36b0f8c5612f"
    strings:
        $input_sa1 = "Request.QueryString.Get" fullword ascii
        $input_sa2 = "Request.Headers.Get" fullword ascii
        $sa1 = "AddressFamily.InterNetwork" fullword ascii
        $sa2 = "Response.AddHeader" fullword ascii
        $sa3 = "Request.InputStream.Read" ascii
        $sa4 = "Response.BinaryWrite" ascii
        $sa5 = "Socket" ascii
        $georg = "Response.Write(\"Georg says, 'All seems fine'\")"

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" ascii
        $tagasp_long10 = "<%@ " ascii
        // <% eval
        $tagasp_long11 = /<% \w/ ascii
        $tagasp_long12 = "<%ex" ascii
        $tagasp_long13 = "<%ev" ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." ascii
        $jsp2 = "=\"javax." ascii
        $jsp3 = "java.lang." ascii
        $jsp4 = "public" fullword ascii
        $jsp5 = "throws" fullword ascii
        $jsp6 = "getValue" fullword ascii
        $jsp7 = "getBytes" fullword ascii

        $perl1 = "PerlScript" fullword ascii


condition:
    any of them
}

rule WEBSHELL_CSHARP_Generic
{
    meta:
        description = "Webshell in c#"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        hash = "b6721683aadc4b4eba4f081f2bc6bc57adfc0e378f6d80e2bfa0b1e3e57c85c7"
        date = "2021/01/11"
        modified = "2023-07-05"
        hash = "4b365fc9ddc8b247a12f4648cd5c91ee65e33fae"
        hash = "019eb61a6b5046502808fb5ab2925be65c0539b4"
        hash = "620ee444517df8e28f95e4046cd7509ac86cd514"
        hash = "a91320483df0178eb3cafea830c1bd94585fc896"

        id = "6d38a6b0-b1d2-51b0-9239-319f1fea7cae"
    strings:
        $input_http = "Request." ascii
        $input_form1 = "<asp:" ascii
        $input_form2 = ".text" ascii
        $exec_proc1 = "new Process" ascii
        $exec_proc2 = "start(" ascii
        $exec_shell1 = "cmd.exe" ascii
        $exec_shell2 = "powershell.exe" ascii

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" ascii
        $tagasp_long10 = "<%@ " ascii
        // <% eval
        $tagasp_long11 = /<% \w/ ascii
        $tagasp_long12 = "<%ex" ascii
        $tagasp_long13 = "<%ev" ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." ascii
        $jsp2 = "=\"javax." ascii
        $jsp3 = "java.lang." ascii
        $jsp4 = "public" fullword ascii
        $jsp5 = "throws" fullword ascii
        $jsp6 = "getValue" fullword ascii
        $jsp7 = "getBytes" fullword ascii

        $perl1 = "PerlScript" fullword ascii


condition:
    any of them
}

rule WEBSHELL_ASP_Runtime_Compile {
    meta:
        description = "ASP webshell compiling payload in memory at runtime, e.g. sharpyshell"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "https://github.com/antonioCoco/SharPyShell"
        date = "2021/01/11"
        modified = "2023-04-05"
        score = 75
        hash = "e826c4139282818d38dcccd35c7ae6857b1d1d01"
        hash = "e20e078d9fcbb209e3733a06ad21847c5c5f0e52"
        hash = "57f758137aa3a125e4af809789f3681d1b08ee5b"
        hash = "bd75ac9a1d1f6bcb9a2c82b13ea28c0238360b3a7be909b2ed19d3c96e519d3d"
        hash = "e44058dd1f08405e59d411d37d2ebc3253e2140385fa2023f9457474031b48ee"
        hash = "f6092ab5c8d491ae43c9e1838c5fd79480055033b081945d16ff0f1aaf25e6c7"
        hash = "dfd30139e66cba45b2ad679c357a1e2f565e6b3140a17e36e29a1e5839e87c5e"
        hash = "89eac7423dbf86eb0b443d8dd14252b4208e7462ac2971c99f257876388fccf2"
        hash = "8ce4eaf111c66c2e6c08a271d849204832713f8b66aceb5dadc293b818ccca9e"
        id = "5da9318d-f542-5603-a111-5b240f566d47"
    strings:
        $payload_reflection1 = "System" fullword ascii
        $payload_reflection2 = "Reflection" fullword ascii
        $payload_reflection3 = "Assembly" fullword ascii
        $payload_load_reflection1 = /[."']Load\b/ ascii
        // only match on "load" or variable which might contain "load"
        $payload_load_reflection2 = /\bGetMethod\(("load|\w)/ ascii
        $payload_compile1 = "GenerateInMemory" ascii
        $payload_compile2 = "CompileAssemblyFromSource" ascii
        $payload_invoke1 = "Invoke" fullword ascii
        $payload_invoke2 = "CreateInstance" fullword ascii
        $payload_xamlreader1 = "XamlReader" fullword ascii
        $payload_xamlreader2 = "Parse" fullword ascii
        $payload_xamlreader3 = "assembly=" ascii
        $payload_powershell1 = "PSObject" fullword ascii
        $payload_powershell2 = "Invoke" fullword ascii
        $payload_powershell3 = "CreateRunspace" fullword ascii
        $rc_fp1 = "Request.MapPath"
        $rc_fp2 = "<body><mono:MonoSamplesHeader runat=\"server\"/>" ascii

        //strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        $asp_input1 = "request" fullword ascii
        $asp_input2 = "Page_Load" fullword ascii
        //  of Request.Form(
        $asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword ascii
        $asp_input4 = "\\u0065\\u0071\\u0075" ascii // equ of Request
        $asp_input5 = "\\u0065\\u0073\\u0074" ascii // est of Request
        $asp_xml_http = "Microsoft.XMLHTTP" fullword ascii
        $asp_xml_method1 = "GET" fullword ascii
        $asp_xml_method2 = "POST" fullword ascii
        $asp_xml_method3 = "HEAD" fullword ascii
        // dynamic form
        $asp_form1 = "<form " ascii
        $asp_form2 = "<Form " ascii
        $asp_form3 = "<FORM " ascii
        $asp_asp   = "<asp:" ascii
        $asp_text1 = ".text" ascii
        $asp_text2 = ".Text" ascii

        $sus_refl1 = " ^= " ascii
        $sus_refl2 = "SharPy" ascii

condition:
    any of them
}

rule WEBSHELL_ASP_SQL
{
    meta:
        description = "ASP webshell giving SQL access. Might also be a dual use tool."
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/03/14"
        modified = "2023-07-05"
        hash = "216c1dd950e0718e35bc4834c5abdc2229de3612"
        hash = "ffe44e9985d381261a6e80f55770833e4b78424bn"
        hash = "3d7cd32d53abc7f39faed133e0a8f95a09932b64"
        hash = "f19cc178f1cfad8601f5eea2352cdbd2d6f94e7e"
        hash = "cafc4ede15270ab3f53f007c66e82627a39f4d0f"

        id = "e534dcb9-40ab-544f-ae55-89fb21c422e9"
    strings:
        $sql1 = "SqlConnection" fullword ascii
        $sql2 = "SQLConnection" fullword ascii
        $sql3 = "System" fullword ascii
        $sql4 = "Data" fullword ascii
        $sql5 = "SqlClient" fullword ascii
        $sql6 = "SQLClient" fullword ascii
        $sql7 = "Open" fullword ascii
        $sql8 = "SqlCommand" fullword ascii
        $sql9 = "SQLCommand" fullword ascii

        $o_sql1 = "SQLOLEDB" fullword ascii
        $o_sql2 = "CreateObject" fullword ascii
        $o_sql3 = "open" fullword ascii

        $a_sql1 = "ADODB.Connection" fullword ascii
        $a_sql2 = "adodb.connection" fullword ascii
        $a_sql3 = "CreateObject" fullword ascii
        $a_sql4 = "createobject" fullword ascii
        $a_sql5 = "open" fullword ascii

        $c_sql1 = "System.Data.SqlClient" fullword ascii
        $c_sql2 = "sqlConnection" fullword ascii
        $c_sql3 = "open" fullword ascii

        $sus1 = "shell" fullword ascii
        $sus2 = "xp_cmdshell" fullword ascii
        $sus3 = "aspxspy" fullword ascii
        $sus4 = "_KillMe" ascii
        $sus5 = "cmd.exe" fullword ascii
        $sus6 = "cmd /c" fullword ascii
        $sus7 = "net user" fullword ascii
        $sus8 = "\\x2D\\x3E\\x7C" ascii
        $sus9 = "Hacker" fullword ascii
        $sus10 = "hacker" fullword ascii
        $sus11 = "HACKER" fullword ascii
        $sus12 = "webshell" ascii
        $sus13 = "equest[\"sql\"]" ascii
        $sus14 = "equest(\"sql\")" ascii
        $sus15 = { e5 bc 80 e5 a7 8b e5 af bc e5 }
        $sus16 = "\"sqlCommand\"" ascii
        $sus17 = "\"sqlcommand\"" ascii

        //$slightly_sus1 = "select * from " ascii
        //$slightly_sus2 = "SELECT * FROM " ascii
        $slightly_sus3 = "SHOW COLUMNS FROM " ascii
        $slightly_sus4 = "show columns from " ascii


        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" ascii
        $tagasp_long10 = "<%@ " ascii
        // <% eval
        $tagasp_long11 = /<% \w/ ascii
        $tagasp_long12 = "<%ex" ascii
        $tagasp_long13 = "<%ev" ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." ascii
        $jsp2 = "=\"javax." ascii
        $jsp3 = "java.lang." ascii
        $jsp4 = "public" fullword ascii
        $jsp5 = "throws" fullword ascii
        $jsp6 = "getValue" fullword ascii
        $jsp7 = "getBytes" fullword ascii

        $perl1 = "PerlScript" fullword ascii


        //strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        $asp_input1 = "request" fullword ascii
        $asp_input2 = "Page_Load" fullword ascii
        //  of Request.Form(
        $asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword ascii
        $asp_xml_http = "Microsoft.XMLHTTP" fullword ascii
        $asp_xml_method1 = "GET" fullword ascii
        $asp_xml_method2 = "POST" fullword ascii
        $asp_xml_method3 = "HEAD" fullword ascii
        // dynamic form
        $asp_form1 = "<form " ascii
        $asp_form2 = "<Form " ascii
        $asp_form3 = "<FORM " ascii
        $asp_asp   = "<asp:" ascii
        $asp_text1 = ".text" ascii
        $asp_text2 = ".Text" ascii

condition:
    any of them
}

rule WEBSHELL_ASP_Scan_Writable
{
    meta:
        description = "ASP webshell searching for writable directories (to hide more webshells ...)"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/03/14"
        modified = "2023-04-05"
        hash = "2409eda9047085baf12e0f1b9d0b357672f7a152"
        hash = "af1c00696243f8b062a53dad9fb8b773fa1f0395631ffe6c7decc42c47eedee7"

        id = "1766e081-0591-59ab-b546-b13207764b4d"
    strings:
        $scan1 = "DirectoryInfo" fullword ascii
        $scan2 = "GetDirectories" fullword ascii
        $scan3 = "Create" fullword ascii
        $scan4 = "File" fullword ascii
        $scan5 = "System.IO" fullword ascii
        // two methods: check permissions or write and delete:
        $scan6 = "CanWrite" fullword ascii
        $scan7 = "Delete" fullword ascii


        $sus1 = "upload" fullword ascii
        $sus2 = "shell" ascii
        $sus3 = "orking directory" fullword ascii
        $sus4 = "scan" ascii


        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" ascii
        $tagasp_long10 = "<%@ " ascii
        // <% eval
        $tagasp_long11 = /<% \w/ ascii
        $tagasp_long12 = "<%ex" ascii
        $tagasp_long13 = "<%ev" ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." ascii
        $jsp2 = "=\"javax." ascii
        $jsp3 = "java.lang." ascii
        $jsp4 = "public" fullword ascii
        $jsp5 = "throws" fullword ascii
        $jsp6 = "getValue" fullword ascii
        $jsp7 = "getBytes" fullword ascii

        $perl1 = "PerlScript" fullword ascii


        //strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        $asp_input1 = "request" fullword ascii
        $asp_input2 = "Page_Load" fullword ascii
        //  of Request.Form(
        $asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword ascii
        $asp_xml_http = "Microsoft.XMLHTTP" fullword ascii
        $asp_xml_method1 = "GET" fullword ascii
        $asp_xml_method2 = "POST" fullword ascii
        $asp_xml_method3 = "HEAD" fullword ascii
        // dynamic form
        $asp_form1 = "<form " ascii
        $asp_form2 = "<Form " ascii
        $asp_form3 = "<FORM " ascii
        $asp_asp   = "<asp:" ascii
        $asp_text1 = ".text" ascii
        $asp_text2 = ".Text" ascii

condition:
    any of them
}

rule WEBSHELL_JSP_ReGeorg
{
    meta:
        description = "Webshell regeorg JSP version"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        reference = "https://github.com/sensepost/reGeorg"
        hash = "6db49e43722080b5cd5f07e058a073ba5248b584"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/01/24"
        modified = "2024-12-09"
        score = 75
        hash = "650eaa21f4031d7da591ebb68e9fc5ce5c860689"
        hash = "00c86bf6ce026ccfaac955840d18391fbff5c933"
        hash = "6db49e43722080b5cd5f07e058a073ba5248b584"
        hash = "9108a33058aa9a2fb6118b719c5b1318f33f0989"

        id = "cbb90005-d8f8-5c64-85d1-29e466f48c25"
    strings:
        $jgeorg1 = "request" fullword ascii
        $jgeorg2 = "getHeader" fullword ascii
        $jgeorg3 = "X-CMD" fullword ascii
        $jgeorg4 = "X-STATUS" fullword ascii
        $jgeorg5 = "socket" fullword ascii
        $jgeorg6 = "FORWARD" fullword ascii

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii 
        $cjsp_short2 = "%>" ascii
        $cjsp_long1 = "<jsp:" ascii 
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii 
        // JSF
        $cjsp_long3 = "/jstl/core" ascii 
        $cjsp_long4 = "<%@p" ascii 
        $cjsp_long5 = "<%@ " ascii 
        $cjsp_long6 = "<% " ascii 
        $cjsp_long7 = "< %" ascii 

condition:
    any of them
}

rule WEBSHELL_JSP_HTTP_Proxy
{
    meta:
        description = "Webshell JSP HTTP proxy"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        hash = "2f9b647660923c5262636a5344e2665512a947a4"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/24"
        modified = "2024-12-09"
        hash = "97c1e2bf7e769d3fc94ae2fc74ac895f669102c6"
        hash = "2f9b647660923c5262636a5344e2665512a947a4"

        id = "55be246e-30a8-52ed-bc5f-507e63bbfe16"
    strings:
        $jh1 = "OutputStream" fullword ascii
        $jh2 = "InputStream" ascii
        $jh3 = "BufferedReader" fullword ascii
        $jh4 = "HttpRequest" fullword ascii
        $jh5 = "openConnection" fullword ascii
        $jh6 = "getParameter" fullword ascii

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii 
        $cjsp_short2 = "%>" ascii
        $cjsp_long1 = "<jsp:" ascii 
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii 
        // JSF
        $cjsp_long3 = "/jstl/core" ascii 
        $cjsp_long4 = "<%@p" ascii 
        $cjsp_long5 = "<%@ " ascii 
        $cjsp_long6 = "<% " ascii 
        $cjsp_long7 = "< %" ascii 

condition:
    any of them
}

rule WEBSHELL_JSP_Writer_Nano
{
    meta:
        description = "JSP file writer"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/24"
        modified = "2024-12-09"
        hash = "ac91e5b9b9dcd373eaa9360a51aa661481ab9429"
        hash = "c718c885b5d6e29161ee8ea0acadb6e53c556513"
        hash = "9f1df0249a6a491cdd5df598d83307338daa4c43"
        hash = "5e241d9d3a045d3ade7b6ff6af6c57b149fa356e"

        id = "422a18f2-d6d4-5b42-be15-1eafe44e01cf"
    strings:
        // writting file to disk
        $payload1 = ".write" ascii
        $payload2 = "getBytes" fullword ascii
        $payload3 = ".decodeBuffer" ascii
        $payload4 = "FileOutputStream" fullword ascii

        // writting using java logging, e.g 9f1df0249a6a491cdd5df598d83307338daa4c43
        $logger1 = "getLogger" fullword ascii 
        $logger2 = "FileHandler" fullword ascii 
        $logger3 = "addHandler" fullword ascii 

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii 
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii 
        $input3 = "getInputStream" fullword ascii 
        $input4 = "getReader" fullword ascii 
        $req1 = "request" fullword ascii 
        $req2 = "HttpServletRequest" fullword ascii 
        $req3 = "getRequest" fullword ascii 

        $jw_sus1 = /getParameter\("."\)/ ascii // one char param
        $jw_sus4 = "yoco" fullword ascii // webshell coder

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii 
        $cjsp_short2 = "%>" ascii
        $cjsp_long1 = "<jsp:" ascii 
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii 
        // JSF
        $cjsp_long3 = "/jstl/core" ascii 
        $cjsp_long4 = "<%@p" ascii 
        $cjsp_long5 = "<%@ " ascii 
        $cjsp_long6 = "<% " ascii 
        $cjsp_long7 = "< %" ascii 

condition:
    any of them
}

rule EXT_WEBSHELL_JSP_Generic_Tiny
{
    meta:
        description = "Generic JSP webshell tiny"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2024-12-16"
        hash = "8fd343db0442136e693e745d7af1018a99b042af"
        hash = "87c3ac9b75a72187e8bc6c61f50659435dbdc4fde6ed720cebb93881ba5989d8"
        hash = "1aa6af726137bf261849c05d18d0a630d95530588832aadd5101af28acc034b5"

        id = "fad14524-de44-52ea-95e6-3e5de3138926"
    strings:
        $payload1 = "ProcessBuilder" fullword ascii
        $payload2 = "URLClassLoader" fullword ascii
        // Runtime.getRuntime().exec(
        $payload_rt1 = "Runtime" fullword ascii
        $payload_rt2 = "getRuntime" fullword ascii
        $payload_rt3 = "exec" fullword ascii

        $jg_sus1 = "xe /c" ascii // of cmd.exe /c
        $jg_sus2 = /getParameter\("."\)/ ascii // one char param
        $jg_sus3 = "</pre>" ascii // webshells like fixed font 
        $jg_sus4 = "BASE64Decoder" fullword ascii 

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii 
        $cjsp_short2 = "%>" ascii
        $cjsp_long1 = "<jsp:" ascii 
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii 
        // JSF
        $cjsp_long3 = "/jstl/core" ascii 
        $cjsp_long4 = "<%@p" ascii 
        $cjsp_long5 = "<%@ " ascii 
        $cjsp_long6 = "<% " ascii 
        $cjsp_long7 = "< %" ascii 

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii 
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii 
        $input3 = "getInputStream" fullword ascii 
        $input4 = "getReader" fullword ascii 
        $req1 = "request" fullword ascii 
        $req2 = "HttpServletRequest" fullword ascii 
        $req3 = "getRequest" fullword ascii 

        // no web input but fixed command to create reverse shell
        $fixed_cmd1 = "bash -i >& /dev/" ascii 

        $fp1 = "Find Security Bugs is a plugin that aims to help security audit.</Details>"
condition:
    any of them
}

rule WEBSHELL_JSP_Generic
{
    meta:
        description = "Generic JSP webshell"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2025-08-18"
        hash = "4762f36ca01fb9cda2ab559623d2206f401fc0b1"
        hash = "bdaf9279b3d9e07e955d0ce706d9c42e4bdf9aa1"
        hash = "ee9408eb923f2d16f606a5aaac7e16b009797a07"

        id = "7535ade8-fc65-5558-a72c-cc14c3306390"
    strings:
        $susp0 = "cmd" fullword ascii 
        $susp1 = "command" fullword ascii 
        $susp2 = "shell" fullword ascii 
        $susp3 = "download" fullword ascii 
        $susp4 = "upload" fullword ascii 
        $susp5 = "Execute" fullword ascii 
        $susp6 = "\"pwd\"" ascii
        $susp7 = "\"</pre>" ascii
        $susp8 = /\\u00\d\d\\u00\d\d\\u00\d\d\\u00\d\d/ ascii
        $susp9 = "*/\\u00" ascii // perfect match of 2 obfuscation methods: /**/\u00xx :)

        $fp1 = "command = \"cmd.exe /c set\";"

        //strings from private rule capa_bin_files
        $dex1 = "dex\n0"
        $dex2 = "dey\n0"
        $pack  = { 50 41 43 4b 00 00 00 02 00 }

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii 
        $cjsp_short2 = "%>" ascii
        $cjsp_long1 = "<jsp:" ascii 
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii 
        // JSF
        $cjsp_long3 = "/jstl/core" ascii 
        $cjsp_long4 = "<%@p" ascii 
        $cjsp_long5 = "<%@ " ascii 
        $cjsp_long6 = "<% " ascii 
        $cjsp_long7 = "< %" ascii 

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii 
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii 
        $input3 = "getInputStream" fullword ascii 
        $input4 = "getReader" fullword ascii 
        $req1 = "request" fullword ascii 
        $req2 = "HttpServletRequest" fullword ascii 
        $req3 = "getRequest" fullword ascii 

        //strings from private rule capa_jsp_payload
        $payload1 = "ProcessBuilder" fullword ascii 
        $payload2 = "processCmd" fullword ascii 
        // Runtime.getRuntime().exec(
        $rt_payload1 = "Runtime" fullword ascii 
        $rt_payload2 = "getRuntime" fullword ascii 
        $rt_payload3 = "exec" fullword ascii 

condition:
    any of them
}

rule WEBSHELL_JSP_Generic_Base64
{
    meta:
        description = "Generic JSP webshell with  encoded payload"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/24"
        modified = "2025-08-18"
        hash = "8b5fe53f8833df3657ae2eeafb4fd101c05f0db0"
        hash = "1b916afdd415dfa4e77cecf47321fd676ba2184d"

        id = "2eabbad2-7d10-573a-9120-b9b763fa2352"
    strings:
        // Runtime
        $one1 = "SdW50aW1l" ascii
        $one2 = "J1bnRpbW" ascii
        $one3 = "UnVudGltZ" ascii
        $one4 = "IAdQBuAHQAaQBtAGUA" ascii
        $one5 = "SAHUAbgB0AGkAbQBlA" ascii
        $one6 = "UgB1AG4AdABpAG0AZQ" ascii
        // exec
        $two1 = "leGVj" ascii
        $two2 = "V4ZW" ascii
        $two3 = "ZXhlY" ascii
        $two4 = "UAeABlAGMA" ascii
        $two5 = "lAHgAZQBjA" ascii
        $two6 = "ZQB4AGUAYw" ascii
        // ScriptEngineFactory
        $three1 = "TY3JpcHRFbmdpbmVGYWN0b3J5" ascii
        $three2 = "NjcmlwdEVuZ2luZUZhY3Rvcn" ascii
        $three3 = "U2NyaXB0RW5naW5lRmFjdG9ye" ascii
        $three4 = "MAYwByAGkAcAB0AEUAbgBnAGkAbgBlAEYAYQBjAHQAbwByAHkA" ascii
        $three5 = "TAGMAcgBpAHAAdABFAG4AZwBpAG4AZQBGAGEAYwB0AG8AcgB5A" ascii
        $three6 = "UwBjAHIAaQBwAHQARQBuAGcAaQBuAGUARgBhAGMAdABvAHIAeQ" ascii


        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii 
        $cjsp_short2 = "%>" ascii
        $cjsp_long1 = "<jsp:" ascii 
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii 
        // JSF
        $cjsp_long3 = "/jstl/core" ascii 
        $cjsp_long4 = "<%@p" ascii 
        $cjsp_long5 = "<%@ " ascii 
        $cjsp_long6 = "<% " ascii 
        $cjsp_long7 = "< %" ascii 

        //strings from private rule capa_bin_files
        $dex1 = "dex\n0"
        $dex2 = "dey\n0"
        $pack  = { 50 41 43 4b 00 00 00 02 00 }

condition:
    any of them
}

rule WEBSHELL_JSP_Generic_ProcessBuilder
{
    meta:
        description = "Generic JSP webshell which uses processbuilder to execute user input"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "82198670ac2072cd5c2853d59dcd0f8dfcc28923"
        hash = "c05a520d96e4ebf9eb5c73fc0fa446ceb5caf343"
        hash = "347a55c174ee39ec912d9107e971d740f3208d53af43ea480f502d177106bbe8"
        hash = "d0ba29b646274e8cda5be1b940a38d248880d9e2bba11d994d4392c80d6b65bd"

        id = "2a7c5f44-24a1-5f43-996e-945c209b79b1"
    strings:
        $exec = "ProcessBuilder" fullword ascii
        $start = "start" fullword ascii

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii 
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii 
        $input3 = "getInputStream" fullword ascii 
        $input4 = "getReader" fullword ascii 
        $req1 = "request" fullword ascii 
        $req2 = "HttpServletRequest" fullword ascii 
        $req3 = "getRequest" fullword ascii 

condition:
    any of them
}

rule WEBSHELL_JSP_Generic_Reflection
{
    meta:
        description = "Generic JSP webshell which uses reflection to execute user input"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2024-12-09"
        hash = "62e6c6065b5ca45819c1fc049518c81d7d165744"
        hash = "bf0ff88cbb72c719a291c722ae3115b91748d5c4920afe7a00a0d921d562e188"

        id = "806ffc8b-1dc8-5e28-ae94-12ad3fee18cd"
    strings:
        $ws_exec = "invoke" fullword ascii
        $ws_class = "Class" fullword ascii
        $fp1 = "SOAPConnection"
        $fp2 = "/CORBA/"

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii 
        $cjsp_short2 = "%>" ascii
        $cjsp_long1 = "<jsp:" ascii 
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii 
        // JSF
        $cjsp_long3 = "/jstl/core" ascii 
        $cjsp_long4 = "<%@p" ascii 
        $cjsp_long5 = "<%@ " ascii 
        $cjsp_long6 = "<% " ascii 
        $cjsp_long7 = "< %" ascii 

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii 
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii 
        $input3 = "getInputStream" fullword ascii 
        $input4 = "getReader" fullword ascii 
        $req1 = "request" fullword ascii 
        $req2 = "HttpServletRequest" fullword ascii 
        $req3 = "getRequest" fullword ascii 

        $cj_encoded1 = "\"java.util.Base64$Decoder\"" ascii
condition:
    any of them
}

rule WEBSHELL_JSP_Generic_Classloader
{
    meta:
        description = "Generic JSP webshell which uses classloader to execute user input"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        hash = "6b546e78cc7821b63192bb8e087c133e8702a377d17baaeb64b13f0dd61e2347"
        date = "2021/01/07"
        modified = "2024-12-09"
        hash = "f3a7e28e1c38fa5d37811bdda1d6b0893ab876023d3bd696747a35c04141dcf0"
        hash = "8ea2a25344e6094fa82dfc097bbec5f1675f6058f2b7560deb4390bcbce5a0e7"
        hash = "b9ea1e9f91c70160ee29151aa35f23c236d220c72709b2b75123e6fa1da5c86c"
        hash = "80211c97f5b5cd6c3ab23ae51003fd73409d273727ba502d052f6c2bd07046d6"
        hash = "8e544a5f0c242d1f7be503e045738369405d39731fcd553a38b568e0889af1f2"

        id = "037e6b24-9faf-569b-bb52-dbe671ab2e87"
    strings:
        $exec = "extends ClassLoader" ascii
        $class = "defineClass" fullword ascii

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii 
        $cjsp_short2 = "%>" ascii
        $cjsp_long1 = "<jsp:" ascii 
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii 
        // JSF
        $cjsp_long3 = "/jstl/core" ascii 
        $cjsp_long4 = "<%@p" ascii 
        $cjsp_long5 = "<%@ " ascii 
        $cjsp_long6 = "<% " ascii 
        $cjsp_long7 = "< %" ascii 

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii 
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii 
        $input3 = "getInputStream" fullword ascii 
        $input4 = "getReader" fullword ascii 
        $req1 = "request" fullword ascii 
        $req2 = "HttpServletRequest" fullword ascii 
        $req3 = "getRequest" fullword ascii 

condition:
    any of them
}

rule WEBSHELL_JSP_Generic_Encoded_Shell
{
    meta:
        description = "Generic JSP webshell which contains cmd or /bin/bash encoded in ascii ord"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-07-05"
        hash = "3eecc354390d60878afaa67a20b0802ce5805f3a9bb34e74dd8c363e3ca0ea5c"
        hash = "f6c2112e3a25ec610b517ff481675b2ce893cb9f"
        hash = "62e6c6065b5ca45819c1fc049518c81d7d165744"

        id = "359949d7-1793-5e13-9fdc-fe995ae12117"
    strings:
        $sj0 = /\{ ?47, 98, 105, 110, 47, 98, 97, 115, 104/ ascii
        $sj1 = /\{ ?99, 109, 100}/ ascii
        $sj2 = /\{ ?99, 109, 100, 46, 101, 120, 101/ ascii
        $sj3 = /\{ ?47, 98, 105, 110, 47, 98, 97/ ascii
        $sj4 = /\{ ?106, 97, 118, 97, 46, 108, 97, 110/ ascii
        $sj5 = /\{ ?101, 120, 101, 99 }/ ascii
        $sj6 = /\{ ?103, 101, 116, 82, 117, 110/ ascii

condition:
    any of them
}

rule WEBSHELL_JSP_NetSpy
{
    meta:
        description = "JSP netspy webshell"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/24"
        modified = "2024-12-09"
        hash = "94d1aaabde8ff9b4b8f394dc68caebf981c86587"
        hash = "3870b31f26975a7cb424eab6521fc9bffc2af580"

        id = "41f5c171-878d-579f-811d-91d74f7e3e24"
    strings:
        $scan1 = "scan" ascii
        $scan2 = "port" ascii
        $scan3 = "web" fullword ascii
        $scan4 = "proxy" fullword ascii
        $scan5 = "http" fullword ascii
        $scan6 = "https" fullword ascii
        $write1 = "os.write" fullword ascii
        $write2 = "FileOutputStream" fullword ascii
        $write3 = "PrintWriter" fullword ascii
        $http = "java.net.HttpURLConnection" fullword ascii

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii 
        $cjsp_short2 = "%>" ascii
        $cjsp_long1 = "<jsp:" ascii 
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii 
        // JSF
        $cjsp_long3 = "/jstl/core" ascii 
        $cjsp_long4 = "<%@p" ascii 
        $cjsp_long5 = "<%@ " ascii 
        $cjsp_long6 = "<% " ascii 
        $cjsp_long7 = "< %" ascii 

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii 
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii 
        $input3 = "getInputStream" fullword ascii 
        $input4 = "getReader" fullword ascii 
        $req1 = "request" fullword ascii 
        $req2 = "HttpServletRequest" fullword ascii 
        $req3 = "getRequest" fullword ascii 

condition:
    any of them
}

rule WEBSHELL_JSP_By_String
{
    meta:
        description = "JSP Webshells which contain unique strings, lousy rule for low hanging fruits. Most are catched by other rules in here but maybe these catch different versions."
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/09"
        modified = "2025-08-18"
        hash = "e9060aa2caf96be49e3b6f490d08b8a996c4b084"
        hash = "4c2464503237beba54f66f4a099e7e75028707aa"
        hash = "06b42d4707e7326aff402ecbb585884863c6351a"
        hash = "dada47c052ec7fcf11d5cfb25693bc300d3df87de182a254f9b66c7c2c63bf2e"
        hash = "f9f6c696c1f90df6421cd9878a1dec51a62e91b4b4f7eac4920399cb39bc3139"
        hash = "f1d8360dc92544cce301949e23aad6eb49049bacf9b7f54c24f89f7f02d214bb"
        hash = "1d1f26b1925a9d0caca3fdd8116629bbcf69f37f751a532b7096a1e37f4f0076"
        hash = "850f998753fde301d7c688b4eca784a045130039512cf51292fcb678187c560b"

        id = "8d64e40b-5583-5887-afe1-b926d9880913"
    strings:
        $jstring1 = "<title>Boot Shell</title>" ascii
        $jstring2 = "String oraPWD=\"" ascii
        $jstring3 = "Owned by Chinese Hackers!" ascii
        $jstring4 = "AntSword JSP" ascii
        $jstring5 = "JSP Webshell</" ascii
        $jstring6 = "motoME722remind2012" ascii
        $jstring7 = "EC(getFromBase64(toStringHex(request.getParameter(\"password" ascii
        $jstring8 = "http://jmmm.com/web/index.jsp" ascii
        $jstring9 = "list.jsp = Directory & File View" ascii
        $jstring10 = "jdbcRowSet.setDataSourceName(request.getParameter(" ascii
        $jstring11 = "Mr.Un1k0d3r RingZer0 Team" ascii
        $jstring12 = "MiniWebCmdShell" fullword ascii
        $jstring13 = "pwnshell.jsp" fullword ascii
        $jstring14 = "session set &lt;key&gt; &lt;value&gt; [class]<br>" ascii
        $jstring15 = "Runtime.getRuntime().exec(request.getParameter(" ascii
        $jstring16 = "GIF98a<%@page" ascii
        $jstring17 = "Tas9er" fullword ascii
        $jstring18 = "uu0028\\u" ascii //obfuscated /
        $jstring19 = "uu0065\\u" ascii //obfuscated e
        $jstring20 = "uu0073\\u" ascii //obfuscated s
        $jstring21 = /\\uuu{0,50}00/ ascii //obfuscated via javas unlimited amount of u in \uuuuuu
        $jstring22 = /[\w\.]\\u(FFFB|FEFF|FFF9|FFFA|200C|202E|202D)[\w\.]/ ascii // java ignores the unicode Interlinear Annotation Terminator inbetween any command
        $jstring23 = "\"e45e329feb5d925b\"" ascii
        $jstring24 = "u<![CDATA[n" ascii

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii 
        $cjsp_short2 = "%>" ascii
        $cjsp_long1 = "<jsp:" ascii 
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii 
        // JSF
        $cjsp_long3 = "/jstl/core" ascii 
        $cjsp_long4 = "<%@p" ascii 
        $cjsp_long5 = "<%@ " ascii 
        $cjsp_long6 = "<% " ascii 
        $cjsp_long7 = "< %" ascii 

        //strings from private rule capa_bin_files
        $dex1 = "dex\n0"
        $dex2 = "dey\n0"
        $pack  = { 50 41 43 4b 00 00 00 02 00 }

condition:
    any of them
}

rule WEBSHELL_JSP_Input_Upload_Write
{
    meta:
        description = "JSP uploader which gets input, writes files and contains \"upload\""
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/24"
        modified = "2024-12-09"
        hash = "ef98ca135dfb9dcdd2f730b18e883adf50c4ab82"
        hash = "583231786bc1d0ecca7d8d2b083804736a3f0a32"
        hash = "19eca79163259d80375ebebbc440b9545163e6a3"

        id = "bbf26edd-88b7-5ec5-a16e-d96a086dcd19"
    strings:
        $upload = "upload" ascii
        $write1 = "os.write" fullword ascii
        $write2 = "FileOutputStream" fullword ascii

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii 
        $cjsp_short2 = "%>" ascii
        $cjsp_long1 = "<jsp:" ascii 
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii 
        // JSF
        $cjsp_long3 = "/jstl/core" ascii 
        $cjsp_long4 = "<%@p" ascii 
        $cjsp_long5 = "<%@ " ascii 
        $cjsp_long6 = "<% " ascii 
        $cjsp_long7 = "< %" ascii 

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii 
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii 
        $input3 = "getInputStream" fullword ascii 
        $input4 = "getReader" fullword ascii 
        $req1 = "request" fullword ascii 
        $req2 = "HttpServletRequest" fullword ascii 
        $req3 = "getRequest" fullword ascii 

condition:
    any of them
}

rule WEBSHELL_Generic_OS_Strings {
    meta:
        description = "typical webshell strings"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/01/12"
        modified = "2024-12-09"
        score = 50
        hash = "d5bfe40283a28917fcda0cefd2af301f9a7ecdad"
        hash = "fd45a72bda0a38d5ad81371d68d206035cb71a14"
        hash = "b4544b119f919d8cbf40ca2c4a7ab5c1a4da73a3"
        hash = "569259aafe06ba3cef9e775ee6d142fed6edff5f"
        hash = "48909d9f4332840b4e04b86f9723d7427e33ac67"
        hash = "0353ae68b12b8f6b74794d3273967b530d0d526f"
        id = "ea85e415-4774-58ac-b063-0f5eb535ec49"
    strings:
        $fp1 = "http://evil.com/" ascii
        $fp2 = "denormalize('/etc/shadow" ascii
      $fp3 = "vim.org>"

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" ascii
        $tagasp_long10 = "<%@ " ascii
        // <% eval
        $tagasp_long11 = /<% \w/ ascii
        $tagasp_long12 = "<%ex" ascii
        $tagasp_long13 = "<%ev" ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." ascii
        $jsp2 = "=\"javax." ascii
        $jsp3 = "java.lang." ascii
        $jsp4 = "public" fullword ascii
        $jsp5 = "throws" fullword ascii
        $jsp6 = "getValue" fullword ascii
        $jsp7 = "getBytes" fullword ascii

        $perl1 = "PerlScript" fullword ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" ascii
        $no_xml2 = "<?xml-stylesheet" ascii
        $no_asp1 = "<%@LANGUAGE" ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ ascii
        $php_new2 = "<?php" ascii
        $php_new3 = "<script language=\"php" ascii

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii 
        $cjsp_short2 = "%>" ascii
        $cjsp_long1 = "<jsp:" ascii 
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii 
        // JSF
        $cjsp_long3 = "/jstl/core" ascii 
        $cjsp_long4 = "<%@p" ascii 
        $cjsp_long5 = "<%@ " ascii 
        $cjsp_long6 = "<% " ascii 
        $cjsp_long7 = "< %" ascii 

        //strings from private rule capa_os_strings
        // windows = nocase
        $w1 = "net localgroup administrators" ascii
        $w2 = "net user" ascii
        $w3 = "/add" ascii
        // linux stuff, case sensitive:
        $l1 = "/etc/shadow" ascii
        $l2 = "/etc/ssh/sshd_config" ascii
        $take_two1 = "net user" ascii
        $take_two2 = "/add" ascii

condition:
    any of them
}

rule WEBSHELL_In_Image
{
    meta:
        description = "Webshell in GIF, PNG or JPG"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        hash = "d4fde4e691db3e70a6320e78657480e563a9f87935af873a99db72d6a9a83c78"
        hash = "84938133ee6e139a2816ab1afc1c83f27243c8ae76746ceb2e7f20649b5b16a4"
        hash = "52b918a64afc55d28cd491de451bb89c57bce424f8696d6a94ec31fb99b17c11"
        date = "2021/02/27"
        modified = "2024-03-11"
        score = 55

        id = "b1185b69-9b08-5925-823a-829fee6fa4cf"
    strings:
        $png = { 89 50 4E 47 }
        $jpg = { FF D8 FF E0 }
        $gif = "GIF8" ascii // doesn't make sense for a GIF but some webshells are utf8 :)
        $gif2 = "gif89" // not a valid gif but used in webshells
        $gif3 = "Gif89" // not a valid gif but used in webshells
        // MS access
        $mdb = { 00 01 00 00 53 74 }
        //$mdb = { 00 01 00 00 53 74 61 6E 64 61 72 64 20 4A 65 74 20 44 42 }

        //strings from private rule capa_php_old_safe
        $php_short = "<?" ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" ascii
        $no_xml2 = "<?xml-stylesheet" ascii
        $no_asp1 = "<%@LANGUAGE" ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ ascii
        $php_new2 = "<?php" ascii
        $php_new3 = "<script language=\"php" ascii

        //strings from private rule capa_php_payload
        // \([^)] to avoid matching on e.g. eval() in comments
        $cpayload1 = /\beval[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload2 = /\bexec[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload3 = /\bshell_exec[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload4 = /\bpassthru[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload5 = /\bsystem[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload6 = /\bpopen[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload7 = /\bproc_open[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload8 = /\bpcntl_exec[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload9 = /\bassert[\n\t ]{0,500}\([^)0]/ ascii
        $cpayload10 = /\bpreg_replace[\n\t ]{0,500}\([^\)]{1,100}\/[ismxADSUXju]{0,11}(e|\\x65)/ ascii
        $cpayload12 = /\bmb_ereg_replace[\t ]{0,500}\([^\)]{1,100}'e'/ ascii
        $cpayload13 = /\bmb_eregi_replace[\t ]{0,500}\([^\)]{1,100}'e'/ ascii
        $cpayload20 = /\bcreate_function[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload21 = /\bReflectionFunction[\n\t ]{0,500}(\([^)]|\/\*)/ ascii
        $cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]{0,500}[,}\)]/ ascii

        $m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]{0,500}(\([^\)]|\/\*)/ ascii
        $m_cpayload_preg_filter2 = "'|.*|e'" ascii
        // TODO backticks

        //strings from private rule capa_php_write_file
        $php_multi_write1 = "fopen(" ascii
        $php_multi_write2 = "fwrite(" ascii
        $php_write1 = "move_uploaded_file" fullword ascii

        //strings from private rule capa_jsp
        $cjsp1 = "<%" ascii 
        $cjsp2 = "<jsp:" ascii 
        $cjsp3 = /language=[\"']java[\"\']/ ascii 
        // JSF
        $cjsp4 = "/jstl/core" ascii 

        //strings from private rule capa_jsp_payload
        $payload1 = "ProcessBuilder" fullword ascii 
        $payload2 = "processCmd" fullword ascii 
        // Runtime.getRuntime().exec(
        $rt_payload1 = "Runtime" fullword ascii 
        $rt_payload2 = "getRuntime" fullword ascii 
        $rt_payload3 = "exec" fullword ascii 

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" ascii
        $tagasp_long10 = "<%@ " ascii
        // <% eval
        $tagasp_long11 = /<% \w/ ascii
        $tagasp_long12 = "<%ex" ascii
        $tagasp_long13 = "<%ev" ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." ascii
        $jsp2 = "=\"javax." ascii
        $jsp3 = "java.lang." ascii
        $jsp4 = "public" fullword ascii
        $jsp5 = "throws" fullword ascii
        $jsp6 = "getValue" fullword ascii
        $jsp7 = "getBytes" fullword ascii

        $perl1 = "PerlScript" fullword ascii


        //strings from private rule capa_asp_payload
        $asp_payload0  = "eval_r" fullword ascii
        $asp_payload1  = /\beval\s/ ascii
        $asp_payload2  = /\beval\(/ ascii
        $asp_payload3  = /\beval\"\"/ ascii
        // var Fla = {'E':eval};  Fla.E(code)
        $asp_payload4  = /:\s{0,10}eval\b/ ascii
        $asp_payload8  = /\bexecute\s?\(/ ascii
        $asp_payload9  = /\bexecute\s[\w"]/ ascii
        $asp_payload11 = "WSCRIPT.SHELL" fullword ascii
        $asp_payload13 = "ExecuteGlobal" fullword ascii
        $asp_payload14 = "ExecuteStatement" fullword ascii
        $asp_payload15 = "ExecuteStatement" fullword ascii
        $asp_multi_payload_one1 = "CreateObject" fullword ascii
        $asp_multi_payload_one2 = "addcode" fullword ascii
        $asp_multi_payload_one3 = /\.run\b/ ascii
        $asp_multi_payload_two1 = "CreateInstanceFromVirtualPath" fullword ascii
        $asp_multi_payload_two2 = "ProcessRequest" fullword ascii
        $asp_multi_payload_two3 = "BuildManager" fullword ascii
        $asp_multi_payload_three1 = "System.Diagnostics" ascii
        $asp_multi_payload_three2 = "Process" fullword ascii
        $asp_multi_payload_three3 = ".Start" ascii
        // this is about "MSXML2.DOMDocument" but since that's easily obfuscated, lets not search for it
        $asp_multi_payload_four1 = "CreateObject" fullword ascii
        $asp_multi_payload_four2 = "TransformNode" fullword ascii
        $asp_multi_payload_four3 = "loadxml" fullword ascii

        // execute cmd.exe /c with arguments using ProcessStartInfo
        $asp_multi_payload_five1 = "ProcessStartInfo" fullword ascii
        $asp_multi_payload_five2 = ".Start" ascii
        $asp_multi_payload_five3 = ".Filename" ascii
        $asp_multi_payload_five4 = ".Arguments" ascii


        //strings from private rule capa_asp_write_file
        // $asp_write1 = "ADODB.Stream" ascii # just a string, can be easily obfuscated
        $asp_always_write1 = /\.write/ ascii
        $asp_always_write2 = /\.swrite/ ascii
        //$asp_write_way_one1 = /\.open\b/ ascii
        $asp_write_way_one2 = "SaveToFile" fullword ascii
        $asp_write_way_one3 = "CREAtEtExtFiLE" fullword ascii
        $asp_cr_write1 = "CreateObject(" ascii
        $asp_cr_write2 = "CreateObject (" ascii
        $asp_streamwriter1 = "streamwriter" fullword ascii
        $asp_streamwriter2 = "filestream" fullword ascii

condition:
    any of them
}

rule WEBSHELL_Mixed_OBFUSC {
   meta:
      description = "Detects webshell with mixed obfuscation commands"
      author = "Arnim Rupp (https://github.com/ruppde)"
      reference = "Internal Research"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      date = "2023-01-28"
      modified = "2023-04-05"
      hash1 = "8c4e5c6bdfcc86fa27bdfb075a7c9a769423ec6d53b73c80cbc71a6f8dd5aace"
      hash2 = "78f2086b6308315f5f0795aeaa75544128f14889a794205f5fc97d7ca639335b"
      hash3 = "3bca764d44074820618e1c831449168f220121698a7c82e9909f8eab2e297cbd"
      hash4 = "b26b5e5cba45482f486ff7c75b54c90b7d1957fd8e272ddb4b2488ec65a2936e"
      hash5 = "e217be2c533bfddbbdb6dc6a628e0d8756a217c3ddc083894e07fd3a7408756c"
      score = 50
      id = "dcb4054b-0c87-5cd0-9297-7fd5f2e37437"
   strings:
      $s1 = "rawurldecode/*" ascii
      $s2 = "preg_replace/*" ascii
      $s3 = " __FILE__/*" ascii
      $s4 = "strlen/*" ascii
      $s5 = "str_repeat/*" ascii
      $s6 = "basename/*" ascii
condition:
    any of them
}

rule WEBSHELL_Cookie_Post_Obfuscation {
    meta:
        description = "Detects webshell using cookie POST"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2023-01-28"
        modified = "2023-04-05"
        license = "https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md"
        hash = "d08a00e56feb78b7f6599bad6b9b1d8626ce9a6ea1dfdc038358f4c74e6f65c9"
        hash = "2ce5c4d31682a5a59b665905a6f698c280451117e4aa3aee11523472688edb31"
        hash = "ff732d91a93dfd1612aed24bbb4d13edb0ab224d874f622943aaeeed4356c662"
        hash = "a3b64e9e065602d2863fcab641c75f5d8ec67c8632db0f78ca33ded0f4cea257"
        hash = "d41abce305b0dc9bd3a9feb0b6b35e8e39db9e75efb055d0b1205a9f0c89128e"
        hash = "333560bdc876fb0186fae97a58c27dd68123be875d510f46098fc5a61615f124"
        hash = "2efdb79cdde9396ff3dd567db8876607577718db692adf641f595626ef64d3a4"
        hash = "e1bd3be0cf525a0d61bf8c18e3ffaf3330c1c27c861aede486fd0f1b6930f69a"
        hash = "f8cdedd21b2cc29497896ec5b6e5863cd67cc1a798d929fd32cdbb654a69168a"

        id = "cc5ded80-5e58-5b25-86d1-1c492042c740"
    strings:
        $s1 = "]($_COOKIE, $_POST) as $"
        $s2 = "function"
        $s3 = "Array"
condition:
    any of them
}
