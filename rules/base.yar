import "pe"
import "math"

rule IDDQD_Godmode_Rule {
   meta:
      description = "This is the most powerful YARA rule. It detects literally everything."
      author = "Florian Roth"
      reference = "Internal Research - get a Godmode YARA rule set with Valhalla by Nextron Systems"
      date = "2019-05-15"
      score = 60
   strings:
      /* Plain strings */
      $s01 = "sekurlsa::logonpasswords" ascii wide nocase           /* Mimikatz Command */
      $s02 = "ERROR kuhl" wide                                      /* Mimikatz Error */
      $s03 = /(@subtee|@mattifestation|@enigma0x3)/ fullword ascii  /* Red Team Tools */
      $s04 = " -w hidden " ascii wide                               /* Power Shell Params */
      $s05 = " -decode " ascii wide                                 /* certutil command */
      $s06 = "Koadic." ascii                                        /* Koadic Framework */
      $s07 = "ReflectiveLoader" fullword ascii wide                 /* Generic - Common Export Name */
      $s08 = "InjectDLL" fullword ascii wide                        /* DLL Injection Keyword */
      $s09 = "[System.Convert]::FromBase64String(" ascii wide       /* PowerShell - Base64 Encoded Payload */
      $s10 = /\\(Release|Debug)\\ms1[2-9]/ ascii                    /* Exploit Codes / PoCs */
      $s11 = "/meterpreter/" ascii                                  /* Metasploit Framework - Meterpreter */
      $s12 = / (-e |-enc |'|")(JAB|SUVYI|aWV4I|SQBFAFgA|aQBlAHgA)/ ascii wide  /* PowerShell Encoded Code */
      $s13 = /  (sEt|SEt|SeT|sET|seT)  / ascii wide                 /* Casing Obfuscation */
      $s14 = ");iex " nocase ascii wide                             /* PowerShell - compact code */
      $s15 = / (cMd\.|cmD\.|CmD\.|cMD\.)/ ascii wide                /* Casing Obfuscation */
      $s16 = /(TW96aWxsYS|1vemlsbGEv|Nb3ppbGxhL|TQBvAHoAaQBsAGwAYQAv|0AbwB6AGkAbABsAGEAL|BNAG8AegBpAGwAbABhAC)/ ascii wide /* Base64 Encoded UA */
      $s17 = "Nir Sofer" fullword wide                              /* Hack Tool Producer */
      $s18 = "web shell by " nocase ascii                           /* Web Shell Copyright */
      $s19 = "impacket." ascii                                      /* Impacket Library */
      $s20 = /\[[\+\-!e]\] (exploit|target|vulnerab|shell|inject|dump)/ nocase  /* Hack Tool Output Pattern */
      $s21 = "ecalper" fullword ascii wide                          /* Reversed String - often found in scripts or web shells */
      $s22 = "0000FEEDACDC}" ascii wide                             /* Squiblydoo - Class ID */
      $s23 = /(click enable editing|click enable content|"Enable Editing"|"Enable Content")/ ascii  /* Phishing Docs */
      $s24 = /vssadmin.{0,4} (delete|resize) shadows|wmic.{0,4} shadowcopy delete/  /* Shadow Copy Deletion - often used in Ransomware */
      $s25 = "stratum+tcp://" nocase                                      /* Stratum Address - used in Crypto Miners */
      $s26 = /\\(Debug|Release)\\(Downloader|Key[lL]og|[Ii]nject|Steal|By[Pp]ass|UAC|Dropper|Loader|CVE\-)/  /* Typical PDB Strings 1 */
      $s27 = /(dropper|downloader|bypass|injection)\.pdb/ nocase    /* Typical PDF strings 2 */
      $s28 = "www.advanced-port-scanner.com" nocase
      $s29 = "famatech.com" nocase
      $s30 = "xmrig" nocase
      $s31 = "minergate" nocase
      /* Combos */
      $xo1 = "Mozilla/5.0" xor ascii wide
      $xf1 = "Mozilla/5.0" ascii wide
   condition:
      1 of ($s*) or
      ( $xo1 and not $xf1 )
}

rule network_tor {
    meta:
        author = "x0r"
        description = "Communications over TOR network"
		    version = "0.1"
		    weight = 4
		    tag = "attack.c2c,attack.exfiltration"
    strings:
        $p1 = "tor\\hidden_service\\private_key" nocase
        $p2 = "tor\\hidden_service\\hostname" nocase
        $p3 = "tor\\lock" nocase
        $p4 = "tor\\state" nocase
        $p5 = "tor\\torrc" nocase
        $p6 = "tor\\geoip" nocase
        $p7 = "tor\\cached-consensus" nocase
        $p8 = "tor\\cached-certs" nocase
        $p9 = "tor\\cached-descriptors" nocase
        $p10 = /[a-z0-9]+\.onion/ nocase
    condition:
        any of them
}

rule network_ssl {
    meta:
        author = "x0r"
        description = "Communications over SSL"
        version = "0.1"
        weight = 4
		    tag = "attack.c2c,attack.exfiltration"
    strings:
        $f1 = "ssleay32.dll" nocase
        $f2 = "libeay32.dll" nocase
        $f3 = "libssl32.dll" nocase
        $c1 = "idsslopenssl" nocase
    condition:
        any of them
}

rule elte_Packed
{
    meta:
      author = "Rachid AZGAOU - ELTE 2019"
	    desc = "rules for packed files detection"
    condition:
		for any i in (0..(pe.number_of_sections)-1) :                                                                      // loop the PE sections
		(
		       pe.sections[i].name == "UPX*"  or                                                                           // check if one of the section with the name "UPX"

		       ( pe.sections[i].raw_data_size==0   and pe.sections[i].characteristics & pe.SECTION_MEM_EXECUTE )  or       // check if the a section has 0 size and its executable

			     math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) >= 7                             // -check if any section has entropy >= 7

		)
}

rule elte_ImportTablePacker {
	meta:
    author = "Rachid AZGAOU - ELTE 2019"
	  desc = "Checking function used for unpacking PE files"
	condition:
		// function used for unpacking
		pe.imports("kernel32.dll", "LoadLibraryA") and   pe.imports("kernel32.dll", "GetProcAddress") and  ( pe.imports("kernel32.dll", "VirtualProtect")
		or pe.imports("kernel32.dll", "VirtualProtectEx")   )
}

rule elte_ImportTableFnc_Debugger {
	meta:
    author = "Rachid AZGAOU - ELTE 2019"
	  desc = "Checking [malicious] functions : debugger."
	condition:
			// function used for checking if the debugger exists (anti VM malwares)
		pe.imports("Kernel32.dll", "IsDebuggerPresent")
		or pe.imports("kernel32.dll", "CheckRemoteDebuggerPresent")
		or pe.imports("NtDll.dll", "DbgBreakPoint")
}
rule elte_ImportTableFnc_InjectProcess {
	meta:
    author = "Rachid AZGAOU - ELTE 2019"
	  desc = "Checking [malicious] functions : process injection"
	condition:
		pe.imports("Advapi32.dll", "AdjustTokenPrivileges")
		or pe.imports("User32.dll", "AttachThreadInput")
		or pe.imports("Kernel32.dll", "CreateRemoteThread") or  pe.imports("Kernel32.dll", "ReadProcessMemory")
		or pe.imports("ntdll.dll", "NtWriteVirtualMemory")  or pe.imports("Kernel32.dll", "WriteProcessMemory")
		or pe.imports("Kernel32.dll", "LoadLibraryExA") or pe.imports("Kernel32.dll", "LoadLibraryExW")
		or pe.imports("ntdll.dll", "LdrLoadDll")          //  Low-level function to load a DLL into a process
}
rule elte_ImportTableFnc_CheckUserisAdmin {
	meta:
    author = "Rachid AZGAOU - ELTE 2019"
	  desc = "Checking [malicious] functions : user is admin?"
	condition:
			// checks if the user has administrator privileges
		pe.imports("advpack.dll", "IsNTAdmin") or pe.imports("advpack.dll", "CheckTokenMembership") or
		pe.imports("Shell32.dll", "IsUserAnAdmin ")
}
rule elte_ImportTableFnc_NetShareEnum {
	meta:
    author = "Rachid AZGAOU - ELTE 2019"
	  desc = "Checking [malicious] functions : NetShareEnum"
	condition:
		pe.imports("Netapi32.dll", "NetShareEnum") 			// Retrieves information about each shared resource on a server

}
rule elte_ImportTableFnc_Http {
	meta:
    author = "Rachid AZGAOU - ELTE 2019"
	  desc = "Checking [malicious] functions : NetShareEnum"
	condition:
    pe.imports("Urlmon.dll", "URLDownloadToFile")
    or pe.imports("wininet.dll", "InternetConnect")
    or pe.imports("wininet.dll", "InternetOpen")
    or pe.imports("wininet.dll", "InternetReadFile")
    or pe.imports("wininet.dll", "InternetWriteFile")
    or pe.imports("wininet.dll", "HttpOpenRequest")
    or pe.imports("wininet.dll", "HttpSendRequest")
    or pe.imports("wininet.dll", "IdHTTPHeaderInfo")
}

rule url_in_proc {
        meta:
          author = "Lionel PRAT"
          desc = "Detect URL in proc"
        strings:
            $uri = /(https?|ftp):\/\/([0-9A-Za-z][0-9A-Za-z-]{0,62})(\.([0-9A-Za-z][0-9A-Za-z-]{0,62}))*(\.?|\b)/ wide nocase
        condition:
            $uri
}

rule uri_on_remote_ip {
        meta:
          author = "Lionel PRAT"
          desc = "Detect URI with ip"
        strings:
            $uri = /[a-zA-Z]+:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\S+/ wide nocase
            $local = /\/127\.0\.0\.|\/192\.168|\/10\.|\/172\.16\./ wide nocase
        condition:
            $uri and not $local
}

rule uri_on_local_ip {
        meta:
          author = "Lionel PRAT"
          desc = "Detect URI with ip"
        strings:
            $uri = /[a-zA-Z]+:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\S+/ wide nocase
            $local = /\/192\.168|\/10\.|\/172\.16\./ wide nocase
        condition:
            $uri and $local
}

rule suspect_smtp_addr {
        meta:
          author = "Lionel PRAT"
          desc = "Detect URI with ip"
        strings:
            $smtp = /smtp\.gmail\.com|smtp\.live\.com|94\.100\.180\.160|smtp\.mail\.yahoo\.com/ wide nocase
        condition:
            $smtp
}

rule stealer {
        meta:
          author = "Lionel PRAT"
          desc = "Detect Steal"
          ref = "https://github.com/cuckoosandbox/community/blob/master/modules/signatures/windows/infostealer_bitcoin.py & https://github.com/fireeye/capa-rules/blob/master/collection/browser/gather-firefox-profile-information.yml"
        strings:
            $wallet = /\\wallet\.dat$|\\bitcoin\\|\\electrum\\|\\multibit\\|\\litecoin\\|\\namecoin\\|\\terracoin\\|\\ppcoin\\|\\primecoin\\|\\feathercoin\\|\\novacoin\\|\\freicoin\\|\\devcoin\\|\\franko\\|\\protoshares\\|\\megacoin\\|\\quarkcoin\\|\\worldcoin\\|\\infinitecoin\\|\\ixcoin\\|\\anoncoin\\|\\bbqcoin\\|\\digitalcoin\\|\\mincoin\\|\\goldcoin\\|\\yacoin\\|\\zetacoin\\|\\fastcoin\\|\\i0coin\\|\\tagcoin\\|\\bytecoin\\|\\florincoin\\|\\phoenixcoin\\|\\luckycoin\\|\\craftcoin\\|\\junkcoin\\/ wide nocase
            $browser = /\\signons\.sqlite|\\secmod\.db|\\cert8\.db|\\key3\.db|\\mozilla\\firefox\\profiles\.ini|select\s+[a-z,\s]{5,}from moz_(logins|cookies)|from moz_(logins|cookies)|where moz_cookies.host like/ nocase wide
            $ftpclient = /\\cuteftp\\sm\.dat|\\cuteftp lite\\sm\.dat|\\cuteftp pro\\sm\.dat|\\flashfxp\\.*\\(sites|quick|history)\.dat|\\vandyke\\config\\sessions\S+|\\ftp explorer\\|\\leechftp\\|\\smartftp\\||\\turboftp\\|\\ftprush\\|\\leapftp\\|\\ftpgetter\\|\\alftp\\|\\ipswitch\\ws_ftp\S+|\\wcx_ftp\.ini|\\32bitftp.ini|\\coffeecup software\\sharedsettings.*(sqlite|ccs)|\\expandrive\\drives\.js|\\filezilla\\(sitemanager|recentservers|filezilla)\.xml|\\software\\simontatham\\putty|\\software\\martin prikryl/ nocase wide
            $imclient = /\\aim\\aimx\.bin|\\digsby\\loginfo\.yaml|\\digsby\\digsby\.dat|\\meebo\\meeboaccounts\.txt|\\miranda\\\S+\.dat|\\myspace\\im\\users\.txt|\\.purple\\accounts\.xml|\\skype\\.*\\config\.xml|\\tencent files\\.*\\qq\\registry\.db|\\trillian\\users\\global\\accounts\.ini|\\xfire\\xfireuser\.ini|\\software\\(wow6432node\\)?google\\google talk\\accounts/ nocase
            $mailclient = /\\microsoft\\windows live mail|\\microsoft\\address book\\.*\.wab|\\microsoft\\outlook express\\.*\.dbx|\\thunderbird\\profiles\\.*\.default|\\appdata\\roaming\\thunderbird\\profiles.ini|\\software\\mozilla\\mozilla thunderbird|\\software\\(wow6432node\\)?incredimail|\\microsoft\\internet account manager\\accounts|\\software\\(wow6432node\\)?microsoft\\windows live mail/ nocase wide
        condition:
            $wallet or $browser or $ftpclient or $imclient or $mailclient
}

rule collect {
meta:
  author = "Lionel PRAT"
  desc = "Collect"
  ref = "https://github.com/fireeye/capa-rules/blob/master/collection/ & https://github.com/cuckoosandbox/community/blob/master/modules/signatures/windows/recon_fingerprint.py"
strings:
    $wmi = /select\s+\*\s+from\s+cim_\S+|select\s+\*\s+from\s+win32_\S+|select\s+\*\s+from\s+msacpi_\S+/ nocase wide
    $public_ip = /bot\.whatismyipaddress\.com|ipinfo\.io\/ip|checkip\.dyndns\.org|ifconfig\.me|ipecho\.net\/plain|api\.ipify\.org|checkip\.amazonaws\.com|icanhazip\.com|wtfismyip\.com\/text|api\.myip\.com/ nocase wide
    $fingerprint = /\\machineguid|\\digitalproductId|\\systembiosdate|windows nt\\currentversion\\installdate/ nocase wide
condition:
    $wmi or $public_ip or $fingerprint
}
