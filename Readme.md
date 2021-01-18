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
```

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
  - DllSuspect: Dll with path or name suspect
  - NetUse: Process use network
  - MutantUse: Process use mutant
  - NetBind: Process Bind socket
  - ProcLegalSuspect: Process legal but can be used to malicious action
  - ProcSuspect: Process with path or name suspect
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
  
  - IRPSuspect: TODO
  - Driver_in_Proc: TODO

## TODO List:
 - Impscan, apihook
 - https://github.com/hasherezade/pe-sieve/wiki use it on vad extract
 - IRP list risk (tag)
 - PE info risk (tag)
 - Proc use driver (handle) make link
