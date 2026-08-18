package ember

import (
	"strings"

	"github.com/edr/scanner/internal/parser"
)

// CommonWindowsDLLs lists 256 DLLs commonly imported by PE files.
var CommonWindowsDLLs = func() []string {
	dlls := make([]string, 256)
	// Populate with known Windows DLLs
	list := []string{
		"kernel32.dll", "ntdll.dll", "user32.dll", "gdi32.dll", "advapi32.dll",
		"comdlg32.dll", "comctl32.dll", "crypt32.dll", "dnsapi.dll", "d3d9.dll",
		"d3d11.dll", "d2d1.dll", "dwrite.dll", "dxgi.dll", "d3dcompiler.dll",
		"dsound.dll", "winmm.dll", "mpr.dll", "mprapi.dll", "mprsnap.dll",
		"msvcrt.dll", "msvcp60.dll", "msvcr90.dll", "msvcp90.dll", "msvcr100.dll",
		"msvcp100.dll", "msvcr110.dll", "msvcp110.dll", "msvcr120.dll", "msvcp120.dll",
		"ucrtbase.dll", "vcruntime140.dll", "mscoree.dll", "mscorlib.dll",
		"ole32.dll", "oleaut32.dll", "oleacc.dll", "olectl.dll",
		"rpcrt4.dll", "rpcns4.dll", "rpcdce.dll",
		"shell32.dll", "shlwapi.dll", "shdocvw.dll",
		"urlmon.dll", "wininet.dll", "winhttp.dll",
		"ws2_32.dll", "wsock32.dll", "wship6.dll",
		"wmi.dll", "wbemprox.dll", "wbemsvc.dll", "fastprox.dll",
		"wldap32.dll", "secur32.dll", "schannel.dll", "ncrypt.dll",
		"bcrypt.dll", "cng.dll", "ksecdd.sys",
		"psapi.dll", "userenv.dll", "netapi32.dll", "srvcli.dll",
		"wtsapi32.dll", "winsta.dll", "cfgmgr32.dll", "devobj.dll",
		"setupapi.dll", "newdev.dll", "hdwwiz.dll",
		"powrprof.dll", "bthprops.dll", "bluetoothapis.dll",
		"iphlpapi.dll", "fwpuclnt.dll", "rasapi32.dll", "rasdlg.dll",
		"sensapi.dll", "sensorsapi.dll", "portabledeviceapi.dll",
		"xmllite.dll", "msxml.dll", "msxml2.dll", "msxml3.dll", "msxml4.dll", "msxml6.dll",
		"xmllite.dll", "xmlrw.dll", "xmlrwrt.dll",
		"ieframe.dll", "browseui.dll", "browselc.dll",
		"activeds.dll", "adsldp.dll", "adsldpc.dll", "adsls.dll",
		"certadm.dll", "certcli.dll", "certenc.dll", "certpoleng.dll",
		"clusapi.dll", "cluadmex.dll", "cmcfg32.dll",
		"corpol.dll", "cryptdlg.dll", "cryptext.dll", "cryptnet.dll",
		"cryptui.dll", "cryptxml.dll", "davclnt.dll",
		"dbgeng.dll", "dbghelp.dll", "dhcpcsvc.dll", "dhcpsapi.dll",
		"dnsrslvr.dll", "drt.dll", "drtprov.dll",
		"efsadu.dll", "els.dll", "elsaid.dll",
		"esent.dll", "esentprf.dll", "evr.dll",
		"fveapi.dll", "fvecerts.dll", "fveui.dll",
		"gpedit.dll", "gpapi.dll", "gptext.dll",
		"hnetcfg.dll", "httpapi.dll", "icm32.dll",
		"icmui.dll", "imaplib.dll", "imapi.dll", "imapi2.dll",
		"imm32.dll", "infosoft.dll", "initpki.dll",
		"input.dll", "inseng.dll", "intl.dll",
		"ipsecsvc.dll", "ipsmsnap.dll", "isatap.dll",
		"iSCSIdsc.dll", "iscsied.dll", "iscsium.dll",
		"jet.dll", "jet500.dll", "jksext.dll",
		"kerberos.dll", "keymgr.dll", "kmsvc.dll",
		"licmgr.dll", "licwmi.dll", "loadperf.dll",
		"localspl.dll", "loghours.dll", "lonsint.dll",
		"lsasrv.dll", "lusrmgr.dll",
		"magnify.dll", "mapi32.dll", "mavinject.dll",
		"mf.dll", "mfcore.dll", "mfplat.dll", "mfplay.dll", "mfsrcsnk.dll",
		"mfvfw.dll", "mgmtapi.dll",
		"microsoft.windows.gdiplus.dll", "migrate.dll",
		"mimefilt.dll", "mll_hp.dll", "mll_mtf.dll",
		"mmc.exe", "mmcndmgr.dll", "mmdrv.dll",
		"mobilened.dll", "mobsync.dll", "modemui.dll",
		"mprddm.dll", "mprmsg.dll", "mqad.dll",
		"mqrt.dll", "msacm.dll", "msad.dll",
		"msafd.dll", "msapsspc.dll", "msaudite.dll",
		"mscms.dll", "msconf.dll", "mscories.dll",
		"msctf.dll", "msctfp.dll", "msctfui.dll",
		"msdadiag.dll", "msdart.dll", "msdasc.dll",
		"msdelta.dll", "msdfmap.dll", "msdmo.dll",
		"msdrm.dll", "msdtc.exe", "msdtckcm.dll",
		"msdtcprx.dll", "msdtcui.dll", "msdtcvsp2.dll",
		"msdxm.ocx", "msfeeds.dll", "msfeedsbs.dll",
		"msftedit.dll", "msg711.dll", "msgsm.dll",
		"mshtml.dll", "msi.dll", "msident.dll",
		"msidle.dll", "msidntld.dll", "msieftp.dll",
		"msihndl.dll", "msimg32.dll", "msimtf.dll",
		"msimsg.dll", "msinfo.dll", "msiwer.dll",
		"mskeyprotect.dll", "msls31.dll", "msmpeg2vdec.dll",
		"msobjs.dll", "msoeacct.dll", "msoeres.dll",
		"msoert2.dll", "msolap.dll", "msolui.dll",
		"msorc32r.dll", "mspatcha.dll", "mspbde40.dll",
		"msprivs.dll", "msr2c.dll", "msratelc.dll",
		"msrdc.dll", "msrdp.ocx", "msrle32.dll",
		"msrpc.dll", "mssbdec.dll", "msscript.ocx",
		"mssign32.dll", "mssip32.dll", "mssitlb.dll",
		"msspell.dll", "mssph.dll", "mssrch.dll",
		"msstdfmt.dll", "msstdmid.dll", "mstask.dll",
		"mster.dll", "mstime.dll", "mstlsapi.dll",
		"mstsc.exe", "mstscax.dll", "msswch.dll",
	}
	copy(dlls, list)
	return dlls
}()

func computeImportFeatures(peInfo *parser.PEInfo) []float32 {
	feat := make([]float32, 1280)
	if peInfo == nil || len(peInfo.ImportedDLLs) == 0 {
		return feat
	}

	// Build a set of imported DLLs (lowercase)
	importSet := make(map[string]bool)
	importCounts := make(map[string]int)
	for _, dll := range peInfo.ImportedDLLs {
		dllLower := strings.ToLower(dll)
		importSet[dllLower] = true
		importCounts[dllLower]++
	}

	for i, dll := range CommonWindowsDLLs {
		base := i * 5
		dllLower := strings.ToLower(dll)
		if importSet[dllLower] {
			feat[base+0] = 1.0 // DLL is imported
			feat[base+1] = float32(importCounts[dllLower]) // import count from this DLL
			feat[base+2] = 1.0 // has imports from this DLL
			// Count how many imports from this DLL
			funcCount := 0
			if len(peInfo.ImportedFunctions) > 0 && len(peInfo.ImportedDLLs) > 0 {
				// Distribute total functions evenly across imported DLLs
				funcCount = len(peInfo.ImportedFunctions) / len(peInfo.ImportedDLLs)
			}
			feat[base+3] = float32(funcCount)
			feat[base+4] = 1.0
		}
	}
	return feat
}
