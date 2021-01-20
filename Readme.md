# Timeline Memory Windows

Analyze memory windows image to create timeline oriented malware search.  
Idea based on calamity: https://github.com/Hestat/calamity  

## Tools Use
  - Loki: https://github.com/Neo23x0/Loki/
  - Clamav: https://github.com/Cisco-Talos/clamav-devel
  - Yara: https://github.com/VirusTotal/yara
  - Volatility3: https://github.com/volatilityfoundation/volatility3
  - Malconf: https://github.com/JPCERTCC/MalConfScan
  - firehol: https://github.com/firehol/firehol
  - capa and floss: https://github.com/fireeye

## Build

```
git clone https://github.com/lprat/timeline_Winmemory
cd timeline_Winmemory
docker build -t timeline_winmemory .
```

## Optionnal

You can use firehol db to check netstat connexion.  
If you want use, please get format created by https://github.com/cybersante/Blacklist_tools/tree/master/generate_bl (db-ipbl.json)  

## Run

```
docker run --rm -ti -v /data/memories_images/:/data/ -v $(pwd)/results:/tmp/results/ timeline_winmemory bash
(Optionnal use firehol -> docker run --rm -ti -v /data/memories_images/:/data/ -v $(pwd)/db-ipbl.json:/db-ipbl.json -v $(pwd)/results:/tmp/results/ timeline_winmemory bash)
$/opt/tools/vol.sh /data/image.raw
#get more info on pid process
$python3 /opt/tools/proc-extract.py /tmp/results/vadinfo.json PID_NUMBER
```

### Features

  - Scan memory with Volatility3
    - windows.vadinfo.VadInfo
    - windows.netscan.NetScan
    - windows.svcscan
    - windows.getservicesids.GetServiceSIDs
    - windows.envars.Envars
    - windows.handles.Handles
    - windows.privileges.Privs
    - windows.driverscan
    - windows.driverirp
    - windows.cmdline.CmdLine
    - windows.psscan.PsScan (dump)
    - windows.modscan.ModScan (dump)
    - windows.dlllist.DllList (dump)
    - windows.malfind.Malfind (dump)
    - windows.vadyarascan.VadYaraScan and yarascan.YaraScan with base.yar
  - Clamav and LokiScan on all dumped files
  - Scan virtual memory type 'EXECUTE' of each process with:
    - PeInfo
    - Capa
    - Floss + YARA
    - ImpScan
    - ObjDump (disass)
  - Make time line in json line to upload on timesketch (vol.jsonl)

## Results

Check Results in $(pwd)/results.  

### Add in timesketch

You can import timeline in timesketch to make fast analyze:
```
 docker exec docker_timesketch_1 tsctl import --file $(pwd)/results/vol.jsonl --username YOU
 Or by web interface!
```

### Tags List

  - Firehol: Connexion use
  - YaraFound: Yara rule detected in memory, more informations in field "MalwareInfo"
  - YaraMalConf: Yara Malconf rule detected in memory, more informations in field "MalwareInfo"
  - ProcMalfind: Vol malfind found
  - PeInjected: Pe in memory, more informations in field "MalwareInfo"
  - PeImpScan: Pe impscan, more informations in field "PEImpScan"
  - DllSuspect: Dll with path or name suspect
  - NetUse: Process use network
  - RDPinUse: RDP connection in progress
  - RATinProgress: RAT tools in progress
  - NetUseSuspect: A legitimate process uses the network abnormally
  - MutantUse: Process use mutant
  - NetBind: Process Bind socket
  - ProcLegalSuspect: Process legal but can be used to malicious action, more informations in field "ProcLegalSuspect"
  - ProcSuspect: Process with path or name suspect or argument (b64, ...)
  - ProcArgsURI: Process launched with URI argument
  - NotPeInfo: Process or module dont contains PeInfo
  - PeNameDiff: Process or module have name different of Peinfo Original or Internal
  - DllPeNameDiff: Dll have name different of Peinfo Original or Internal
  - ModSuspect: Module with path or name suspect
  - ClamFound: Clamav detect thret on Module or Process, more informations in field "MalwareInfo"
  - LokiFound: Loki detect thret on Module or Process, more informations in field "MalwareInfo"
  - ServiceSuspect: Service with suspect name
  - Started_From_Service: Process started from service
  - Driver_in_Service: Service use driver
  - Linked_with_SuspectProc: Service realtionship with suspect process
  - Linked_with_SuspectDriver: Service realtionship with suspect module
  - Autorun: service runned at windows start
  - Running: service in running
  - FileDangerous: Suspect file in memory inside home user (can be used for execution malware => pe, script)
  - FileSuspect: Suspect file in memory inside home user (can be used for initial access)
  - Driver_in_Proc: TODO

## TODO List:
 - apihook
 - https://github.com/hasherezade/pe-sieve/wiki use it on vad extract
 - Proc use driver (handle) make link
