#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, sys
import shutil
import json
import subprocess
import pefile
import re
import traceback
import ipaddress
from datetime import datetime, timedelta
filex={}
modulez={}
db={}
db_net={}
db_mod={}
db_serv={}
date_deb=None
serv_sid={}
firehol=None
driverx={}
driverirpx={}

if os.path.isfile('/db-ipbl.json'):
    with open("/db-ipbl.json", encoding='utf-8') as fp:
        try:
            firehol = json.load(fp)
        except Exception as err:
            print("Error to open: /db-ipbl.json")
with open("/tmp/results/listfiles.json", encoding='utf-8') as fp:
    try:
        filex = json.load(fp)
    except Exception as err:
        print("Error to open: /tmp/results/listfiles.json")
with open("/tmp/results/listmodules.json", encoding='utf-8') as fp:
    try:
        modulez = json.load(fp)
    except Exception as err:
        print("Error to open: /tmp/results/listmodules.json")
with open("/tmp/results/driverscan.json", encoding='utf-8') as fp:
    try:
        driverx = json.load(fp)
    except Exception as err:
        print("Error to open: /tmp/results/driverscan.json")
with open("/tmp/results/driverirp.json", encoding='utf-8') as fp:
    try:
        driverirpx = json.load(fp)
    except Exception as err:
        print("Error to open: /tmp/results/driverirp.json ")
with open("/tmp/results/svcscan-sid.json", encoding='utf-8') as fp:
    try:
        serv_sid = json.load(fp)
    except Exception as err:
        print("Error to open: /tmp/results/svcscan-sid.json")
cfiles={"/tmp/results/psscan.json": "proc", "/tmp/results/cmdline.json": "cmdline", "/tmp/results/env.json": "env", "/tmp/results/netscan.json": "netscan", "/tmp/results/priv.json": "priv", "/tmp/results/handle.json": "handle", "/tmp/results/vadinfo.json": "vad", "/tmp/results/dlllist.json": "dlllist", "/tmp/results/malfind.json": "malfind", "/tmp/results/yara.json": "yara", "/tmp/results/yara-malconf.json": "yara"}
for k,v in cfiles.items():
    with open(k, encoding='utf-8') as fp:
        try:
            ds = json.load(fp)
            for d in ds:
                if not 'PID' in d and not v=='yara':
                    print("Error no PID in json: "+k)
                    print("\t"+str(d))
                    continue
                pid=None
                if v=='yara' and 'Pid' in d and d['Pid']:
                    pid=d['Pid']
                elif d['PID']:
                    pid=d['PID']
                else:
                    print("Error no PID in json: "+k)
                    print("\t"+str(d))
                    continue
                if pid == 4 and 'CreateTime' in d and d['CreateTime']:
                    date_deb=d['CreateTime']
                if pid not in db:
                    db[pid] = {'tag':[]}
                if v=='env':
                    if 'EnvVar' not in db[pid]:
                        db[pid]['EnvVar'] = []
                    if 'Variable' in d and d['Variable'] and 'Value' in d and d['Value'] and d['Variable']+"="+d['Value'] not in db[pid]['EnvVar']:
                        db[pid]['EnvVar'].append(d['Variable']+"="+d['Value'])
                    continue
                if v=='yara':
                    if 'YaraFound' not in db[pid]['tag']:
                        db[pid]['tag'].append('YaraFound')
                    if 'malconf' in k:
                        if 'YaraMalConf' not in db[pid]['tag']:
                            db[pid]['tag'].append('YaraMalConf')
                    if 'MalwareInfo' not in db[pid]:
                        db[pid]['MalwareInfo'] = []
                    val=bytes.fromhex(d['Value'].replace('00','').replace(' ','')).decode('utf-8',"ignore")
                    if 'YaraMemScan|'+d['Rule']+'|'+val not in db[pid]['MalwareInfo']:
                        db[pid]['MalwareInfo'].append('YaraMemScan|'+d['Rule']+'|'+val)
                    continue
                if v=='malfind':
                    if 'ProcMalfind' not in db[pid]['tag']:
                        db[pid]['tag'].append('ProcMalfind')
                    continue
                if v=='vad':
                    hex_string = format(d['Start VPN'], '#04x')
                    hex_string2 = format(d['End VPN'], '#04x')
                    fnamex='pid.'+str(d['PID'])+'.vad.'+hex_string+'-'+hex_string2
                    if os.path.isfile('/tmp/results/'+fnamex+'.yarafound'):
                        if 'YaraFound' not in db[pid]['tag']:
                            db[pid]['tag'].append('YaraFound')
                        if 'MalwareInfo' not in db[pid]:
                            db[pid]['MalwareInfo'] = []
                        with open('/tmp/results/'+fnamex+'.yarafound') as yfp:
                            rule=None
                            matchs=[]
                            for line in yfp:
                                line=line.strip()
                                if line.endswith('.floss'):
                                    if rule:
                                        val='YaraVad|'+rule+'|'+'|'.join(list(set(matchs)))
                                        if val not in db[pid]['MalwareInfo']:
                                            db[pid]['MalwareInfo'].append(val)
                                        matchs=[]
                                    res=line.split(' ')
                                    rule=res[0]
                                else:
                                    if rule:
                                        res=line.split(':')
                                        if len(res)>2:
                                            matchs.append((':'.join(res[2:])).strip())
                            if rule:
                                val='YaraVad|'+rule+'|'+'|'.join(list(set(matchs)))
                                if val not in db[pid]['MalwareInfo']:
                                    db[pid]['MalwareInfo'].append(val)
                    if os.path.isfile('/tmp/results/'+fnamex+'.capa'):
                        if 'PeInjected' not in db[pid]['tag']:
                            db[pid]['tag'].append('PeInjected')
                        if 'MalwareInfo' not in db[pid]:
                            db[pid]['MalwareInfo'] = []
                        with open('/tmp/results/'+fnamex+'.capa') as yfp:
                            tag_ma=False
                            tag_mbc=False
                            tag_cap=False
                            for line in yfp:
                                if line.startswith('|') and not line.startswith('|---'):
                                    if tag_ma:
                                        res=line.split('|')
                                        if len(res) == 4:
                                            val='Capa_MA|'+res[1].strip()+'|'+res[2].strip()
                                            if val not in db[pid]['MalwareInfo']:
                                                db[pid]['MalwareInfo'].append(val)
                                    if tag_mbc:
                                        res=line.split('|')
                                        if len(res) == 4:
                                            val='Capa_MBC|'+res[1].strip()+'|'+res[2].strip()
                                            if val not in db[pid]['MalwareInfo']:
                                                db[pid]['MalwareInfo'].append(val)
                                    if tag_cap:
                                        res=line.split('|')
                                        if len(res) == 4:
                                            val='Capa_CAPA|'+res[1].strip()+'|'+res[2].strip()
                                            if val not in db[pid]['MalwareInfo']:
                                                db[pid]['MalwareInfo'].append(val)
                                if '| ATT&CK Tactic' in line:
                                    tag_ma=True
                                    tag_mbc=False
                                    tag_cap=False
                                if '| MBC Objective' in line:
                                    tag_ma=False
                                    tag_mbc=True
                                    tag_cap=False
                                if '| CAPABILITY' in line:
                                    tag_ma=False
                                    tag_mbc=False
                                    tag_cap=True
                    if os.path.isfile('/tmp/results/'+fnamex+'.peinfo'):
                        if 'PeInjected' not in db[pid]['tag']:
                            db[pid]['tag'].append('PeInjected')
                        with open('/tmp/results/'+fnamex+'.peinfo') as yfp:
                            try:
                                peinfox = json.load(yfp)
                                if 'PeInjected' not in db[pid]:
                                    db[pid]['PeInjected']=[]
                                db[pid]['PeInjected'].append(str(peinfox))
                            except Exception as err:
                                print("Error to open: "+'/tmp/results/'+d['File output']+'.peinfo')
                    continue
                if v=='dlllist':
                    if 'DllList' not in db[pid]:
                        db[pid]['DllList'] = []
                    if 'Path' in d and d['Path'] and d['Path'] not in db[pid]['DllList']:
                        db[pid]['DllList'].append(d['Path'])
                        suspect=False
                        if not d['Path'].lower().endswith('.dll') or ':\\windows\\' not in d['Path'].lower() or re.match(r"[bcdfghjklmnpqrstvwxz0-9]{6}|[aeuoiy0-9]{5}", d['Name'].lower()):
                            suspect=True
                            if "DllSuspect" not in db[pid]['tag']:
                                db[pid]['tag'].append("DllSuspect")
                        if 'File output' in d and d['File output'].endswith('.dmp') and suspect:
                            pepath=filex['pa'][d['File output']]
                            try:
                                pe = pefile.PE(pepath)
                                files_info = {}
                                peimp=[]
                                peexp=[]
                                pe.parse_data_directories(directories=pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"])
                                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                                        for imp in entry.imports:
                                            tmpval=""
                                            if entry.dll:
                                                tmpval=entry.dll.decode(errors='replace')
                                            if imp.name:
                                                if tmpval:
                                                    tmpval+=' -> '
                                                tmpval+=imp.name.decode(errors='replace')
                                            peimp.append(tmpval)
                                pe.parse_data_directories(directories=pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"])
                                if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                                    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                                        if exp.name:
                                            peexp.append(exp.name.decode(errors='replace'))
                                if peimp:
                                    if 'PEImport' not in db[pid]:
                                        db[pid]['PEImport'] = []
                                    db[pid]['PEImport'] = peimp
                                    db[pid]['PEImport']=list(set(db[pid]['PEImport']))
                                if peexp:
                                    if 'PEExport' not in db[pid]:
                                        db[pid]['PEExport'] = []
                                    db[pid]['PEExport'] = peexp
                                    db[pid]['PEExport']=list(set(db[pid]['PEExport']))
                                if hasattr(pe, 'FileInfo'):
                                    for fileinfo in pe.FileInfo:
                                        fileinfo = fileinfo[0]
                                        if fileinfo.Key == b'StringFileInfo':
                                            for st in fileinfo.StringTable:
                                                for entry in st.entries.items():
                                                    files_info[entry[0].decode("ascii","ignore")] = entry[1].decode("ascii","ignore")
                                if files_info:
                                    if 'DllSuspect' not in db[pid]:
                                        db[pid]['DllSuspect'] = []
                                    db[pid]['DllSuspect'].append(d['Name']+'|'+str(files_info))
                            except Exception as e:
                                print("[-] PEFormatError: %s" % str(e))
                    continue
                if v=='priv':
                    if 'Priv' not in db[pid]:
                        db[pid]['Priv'] = []
                    if 'Privilege' in d and d['Privilege'] and 'Description' in d and d['Description'] and d['Privilege']+"("+d['Description']+")" not in db[pid]['Priv']:
                        #TODO add tag if suspect priv
                        db[pid]['Priv'].append(d['Privilege']+"("+d['Description']+")")
                    continue
                if v=='handle':
                    if 'Handle' not in db[pid]:
                        db[pid]['Handle'] = []
                    if 'Name' in d and d['Name'] and 'Type' in d and d['Type'] and d['Type']+"|"+d['Name'] not in db[pid]['Handle']:
                        db[pid]['Handle'].append(d['Type']+"|"+d['Name'])
                    continue
                if v=='netscan':
                    if not "LISTENING" in d['State']:
                        if "NetUse" not in db[pid]['tag']:
                            db[pid]['tag'].append("NetUse")
                        if 'NetUse' not in db[pid]:
                            db[pid]['NetUse'] = []
                        if d['Proto']+"|"+d['LocalAddr']+":"+str(d['LocalPort'])+"|"+d['ForeignAddr']+":"+str(d['ForeignPort'])+"|"+d['State'] not in db[pid]['NetUse']:
                            db[pid]['NetUse'].append(d['Proto']+"|"+d['LocalAddr']+":"+str(d['LocalPort'])+"|"+d['ForeignAddr']+":"+str(d['ForeignPort'])+"|"+d['State'])
                    if "LISTENING" in d['State']:
                        if "NetUse" not in db[pid]['tag']:
                            db[pid]['tag'].append("NetUse")
                        if 'NetBind' not in db[pid]:
                            db[pid]['NetBind'] = []
                        if d['Proto']+"|"+d['LocalAddr']+":"+str(d['LocalPort']) not in db[pid]['NetBind']:
                            db[pid]['NetBind'].append(d['Proto']+"|"+d['LocalAddr']+":"+str(d['LocalPort']))
                    #firehol
                    if firehol:
                        if not ipaddress.ip_address(d["ForeignAddr"]).is_private and d["ForeignAddr"] in firehol:
                            if "Firehol" not in db[pid]['tag']:
                                db[pid]['tag'].append("Firehol")
                            if not 'firehol' in db[pid]:
                                db[pid]["firehol"] = []
                            db[pid]["firehol"]+=firehol[d["ForeignAddr"]]
                            db[pid]["firehol"]=list(set(db[pid]["firehol"]))
                    continue
                if v=='proc':
                    if 'File output' in d and d['File output'] and d['File output'].endswith('.dmp'):
                        pepath=filex['pa'][d['File output']]
                        try:
                            pe = pefile.PE(pepath)
                            files_info = {}
                            peimp=[]
                            peexp=[]
                            pe.parse_data_directories(directories=pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"])
                            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                                    for imp in entry.imports:
                                        tmpval=""
                                        if entry.dll:
                                            tmpval=entry.dll.decode(errors='replace')
                                        if imp.name:
                                            if tmpval:
                                                tmpval+=' -> '
                                            tmpval+=imp.name.decode(errors='replace')
                                        peimp.append(tmpval)
                            pe.parse_data_directories(directories=pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"])
                            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                                    if exp.name:
                                        peexp.append(exp.name.decode(errors='replace'))
                            if peimp:
                                if 'PEImport' not in db[pid]:
                                    db[pid]['PEImport'] = []
                                db[pid]['PEImport'] = peimp
                                db[pid]['PEImport']=list(set(db[pid]['PEImport']))
                            if peexp:
                                if 'PEExport' not in db[pid]:
                                    db[pid]['PEExport'] = []
                                db[pid]['PEExport'] = peexp
                                db[pid]['PEExport']=list(set(db[pid]['PEExport']))
                            if hasattr(pe, 'FileInfo'):
                                for fileinfo in pe.FileInfo:
                                    fileinfo = fileinfo[0]
                                    if fileinfo.Key == b'StringFileInfo':
                                        for st in fileinfo.StringTable:
                                            for entry in st.entries.items():
                                                files_info[entry[0].decode("ascii","ignore")] = entry[1].decode("ascii","ignore")
                            if files_info:
                                if 'PeInfo' not in db[pid]:
                                    db[pid]['PeInfo'] = []
                                for kx,vx in files_info.items():
                                    if kx+"=="+vx not in db[pid]['PeInfo']:
                                        #TODO tag if internalname != ImageFileName | not microsoft
                                        db[pid]['PeInfo'].append(kx+"=="+vx)
                        except Exception as e:
                            print("[-] PEFormatError: %s" % str(e))
                if 'CreateTime' in d and d['CreateTime'] and 'CreateTime' not in db[pid]:
                    db[pid]['CreateTime'] = d['CreateTime']
                if 'ImageFileName' in d and d['ImageFileName'] and 'ImageFileName' not in db[pid]:
                    db[pid]['ImageFileName'] = d['ImageFileName']
                    if d['ImageFileName'].lower() in ["svchost.exe", "powershell.exe", "regsvr32.exe", "bcdedit.exe", "mshta.exe", "schtasks.exe","wmic.exe", "cmd.exe", "rundll32.exe"]:
                        if "ProcLegalSuspect" not in db[pid]['tag']:
                            db[pid]['tag'].append("ProcLegalSuspect")
                if 'PPID' in d and d['PPID'] and 'PPID' not in db[pid]:
                    db[pid]['PPID'] = d['PPID']
                if 'SessionId' in d and d['SessionId'] and 'SessionId' not in db[pid]:
                    db[pid]['SessionId'] = d['SessionId']
                if 'Args' in d and d['Args'] and 'cmdline' not in db[pid]:
                    db[pid]['cmdline'] = d['Args']
                    if not d['Process'].lower().endswith('.exe') or '\\appdata\\' in d['Args'].lower() or '\\users\\' in d['Args'].lower() or re.match(r"[bcdfghjklmnpqrstvwxz0-9]{6}|[aeuoiy0-9]{5}", d['Process'].lower()):
                        if "ProcSuspect" not in db[pid]['tag']:
                            db[pid]['tag'].append("ProcSuspect")
        except Exception as err:
            print("Error to open: "+k+" -- "+str(err))
            traceback.print_exc(file=sys.stdout)
with open("/tmp/results/modscan.json", encoding='utf-8') as fp:
    try:
        ds = json.load(fp)
        for d in ds:
            db_mod[d['Path']]={'CreateTime': date_deb, 'File': d['File output'], 'ImageFileName': d['Name'], 'tag':[]}
            suspect=False
            if 'Base' in d and d['Base']:
                for driv in driverx:
                    if 'Start' in driv and driv['Start'] and d['Base'] == driv['Start']:
                        if 'Driver Name' not in db_mod[d['Path']]:
                            db_mod[d['Path']]['Driver Name']=[]
                        if 'Driver Name' in driv and driv['Driver Name'] not in db_mod[d['Path']]['Driver Name']:
                            db_mod[d['Path']]['Driver Name'].append(driv['Driver Name'])
                            for drivirp in driverirpx:
                                if 'Driver Name' in drivirp and drivirp['Driver Name'] == driv['Driver Name']:
                                    if 'IRP' in drivirp and drivirp['IRP']:
                                        val=drivirp['IRP']
                                        if 'Symbol' in drivirp and drivirp['Symbol']:
                                            val+='|'+drivirp['Symbol']
                                        if 'IRP_Symbol' not in db_mod[d['Path']]:
                                            db_mod[d['Path']]['IRP_Symbol']=[]
                                        if val not in  db_mod[d['Path']]['IRP_Symbol']:
                                            db_mod[d['Path']]['IRP_Symbol'].append(val)
                        if 'Driver Path' not in db_mod[d['Path']]:
                            db_mod[d['Path']]['Driver Path']=[]
                        if 'Name' in driv and driv['Name'] not in db_mod[d['Path']]['Driver Path']:
                            db_mod[d['Path']]['Driver Path'].append(driv['Name'])
            if d['Path'].lower().endswith('.sys') and '\\System32\\drivers\\' in d['Path'].lower():
                suspect=False
            elif d['Path'].lower().endswith('.dll') and '\\System32\\' in d['Path'].lower():
                suspect=False
            elif '\\SystemRoot\\system32\\ntoskrnl.exe' == d['Path']:
                suspect=False
            else:
                suspect=True
            if re.match(r"[bcdfghjklmnpqrstvwxz0-9]{6}|[aeuoiy0-9]{5}", d['Name'].lower()):
                suspect=True
            if suspect and "ModSuspect" not in db_mod[d['Path']]['tag']:
                db_mod[d['Path']]['tag'].append("ModSuspect")
            if not d['File output'].endswith('.dmp'):
                continue
            pepath=modulez['pa'][d['File output']]
            try:
                pe = pefile.PE(pepath)
                files_info = {}
                peimp=[]
                peexp=[]
                pe.parse_data_directories(directories=pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"])
                pe.parse_data_directories(directories=pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"])
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        for imp in entry.imports:
                            tmpval=""
                            if entry.dll:
                                tmpval=entry.dll.decode(errors='replace')
                            if imp.name:
                                if tmpval:
                                    tmpval+=' -> '
                                tmpval+=imp.name.decode(errors='replace')
                            peimp.append(tmpval)
                pe.parse_data_directories(directories=pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"])
                if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                        if exp.name:
                            peexp.append(exp.name.decode(errors='replace'))
                if peimp:
                    if 'PEImport' not in db_mod[d['Path']]:
                        db_mod[d['Path']]['PEImport'] = []
                    db_mod[d['Path']]['PEImport'] = peimp
                    db_mod[d['Path']]['PEImport']=list(set(db_mod[d['Path']]['PEImport']))
                if peexp:
                    if 'PEExport' not in db_mod[d['Path']]:
                        db_mod[d['Path']]['PEExport'] = []
                    db_mod[d['Path']]['PEExport'] = peexp
                    db_mod[d['Path']]['PEExport']=list(set(db_mod[d['Path']]['PEExport']))
                if hasattr(pe, 'FileInfo'):
                    for fileinfo in pe.FileInfo:
                        fileinfo = fileinfo[0]
                        if fileinfo.Key == b'StringFileInfo':
                            for st in fileinfo.StringTable:
                                for entry in st.entries.items():
                                    files_info[entry[0].decode("ascii","ignore")] = entry[1].decode("ascii","ignore")
                if files_info:
                    if 'PeInfo' not in db_mod[d['Path']]:
                        db_mod[d['Path']]['PeInfo'] = []
                    for kx,vx in files_info.items():
                        if kx+"=="+vx not in db_mod[d['Path']]['PeInfo']:
                            #TODO tag if internalname != ImageFileName | not microsoft
                            db_mod[d['Path']]['PeInfo'].append(kx+"=="+vx)
            except Exception as e:
                print("[-] PEFormatError: %s" % str(e))
    except Exception as err:
        print("Error to open: /tmp/results/modscan.json"+" -- "+str(err))
        traceback.print_exc(file=sys.stdout)
with open("/tmp/results/clamavresults.log", encoding='utf-8') as fp:
    for line in fp:
        res=line.strip().split(':')
        if res[0] in filex['pi']:
            pid=filex['pi'][res[0]]
            if 'MalwareInfo' not in db[pid]:
                db[pid]['MalwareInfo'] = []
            if 'ClamFound' not in db[pid]['tag']:
                db[pid]['tag'].append('ClamFound')
            if 'ClamScan|'+res[1].strip() not in db[pid]['MalwareInfo']:
                db[pid]['MalwareInfo'].append('ClamScan|'+res[1].strip())
        elif res[0] in modulez['fn']:
            for k,v in db_mod.items():
                if res[0] in v['File']:
                    if 'MalwareInfo' not in v:
                        db_mod[k]['MalwareInfo']=[]
                    if 'ClamFound' not in db_mod[k]['tag']:
                        db_mod[k]['tag'].append('ClamFound')
                    if 'ClamScan|'+res[1].strip() not in db_mod[k]['MalwareInfo']:
                        db_mod[k]['MalwareInfo'].append('ClamScan|'+res[1].strip())
        else:
            print("Error to found file clamav: "+line)
with open("/tmp/results/lokiresults.log", encoding='utf-8') as fp:
    r=re.compile(",FileScan,FILE:\s+(?P<path>.*)\s+SCORE:\s+.*\s+Yara Rule MATCH:\s+(?P<rule>.*)\s+SUBSCORE:\s+.*\s+(MATCHES:\s+(?P<strings>.*)$)?")
    for line in fp:
        if not ',FileScan,FILE:' in line:
            continue
        #refind
        #recup: path, yara rule, str found
        for m in r.finditer(line):
            ret=m.groupdict()
            if 'path' in ret and ret['path']:
                if ret['path'] in filex['pi']:
                    pid=filex['pi'][ret['path']]
                    if 'MalwareInfo' not in db[pid]:
                        db[pid]['MalwareInfo'] = []
                    if 'LokiFound' not in db[pid]['tag']:
                        db[pid]['tag'].append('LokiFound')
                    val="LokiScan|"
                    if 'rule' in ret and ret['rule']:
                        val+=ret['rule']
                    val+="|"
                    if 'strings' in ret and ret['strings']:
                        val+=ret['strings']
                    if val not in db[pid]['MalwareInfo']:
                        db[pid]['MalwareInfo'].append(val)
                elif ret['path'] in modulez['fn']:
                    for k,v in db_mod.items():
                        if modulez['fn'] in v['File']:
                            if 'MalwareInfo' not in v:
                                db_mod[k]['MalwareInfo']=[]
                            if 'LokiFound' not in db_mod[k]['tag']:
                                db_mod[k]['tag'].append('LokiFound')
                            val="LokiScan|"
                            if 'rule' in ret and ret['rule']:
                                val+=ret['rule']
                            val+="|"
                            if 'strings' in ret and ret['strings']:
                                val+=ret['strings']
                            if val not in db_mod[k]['MalwareInfo']:
                                db_mod[k]['MalwareInfo'].append(val)
                else:
                    print("Error to found file loki: "+line)
fjsonl = open("/tmp/results/vol.jsonl", "a", encoding='utf-8')
now = datetime.now()
with open("/tmp/results/netscan.json", encoding='utf-8') as fp:
    try:
        ds = json.load(fp)
        for d in ds:
            #write direct in jsonl
            jsonl = {"message": '('+d['Proto']+')'+d['LocalAddr']+':'+str(d['LocalPort'])+'--'+d['State']+'-->'+d['ForeignAddr']+':'+str(d['ForeignPort']), "timestamp_desc": "Netstat", "tag":[]}
            if "PID" in d and d["PID"]:
                jsonl["PID"] = str(d["PID"])
            if "Owner" in d and d["Owner"] and d["Owner"] != "*":
                jsonl["Process"] = str(d["Owner"])
            if "ForeignAddr" in d and d["ForeignAddr"]:
                jsonl["IP_DST"] = str(d["ForeignAddr"])
            if "ForeignPort" in d and d["ForeignPort"]:
                jsonl["PORT_DST"] = str(d["ForeignPort"])
            if "LocalAddr" in d and d["LocalAddr"]:
                jsonl["IP_SRC"] = str(d["LocalAddr"])
            if "LocalPort" in d and d["LocalPort"]:
                jsonl["PORT_SRC"] = str(d["LocalPort"])
            if "LocalPort" in d and d["LocalPort"]:
                jsonl["PORT_SRC"] = str(d["LocalPort"])
            if "Proto" in d and d["Proto"]:
                jsonl["Protocol"] = str(d["Proto"])
            if "State" in d and d["State"]:
                jsonl["State"] = str(d["State"])
            date = now
            if "Created" in d and d["Created"]:
                # add date of file
                try:
                    date = datetime.strptime(d["Created"], "%Y-%m-%dT%H%M%S") #2020-02-07T10:46:52
                except:
                    date = now
                    jsonl["tag"].append("unknown_date")
            else:
                try:
                    date = datetime.strptime(date_deb, "%Y-%m-%dT%H%M%S")
                except:
                    date = now
                jsonl["tag"].append("unknown_date")
            jsonl["timestamp"] = int(str(int(datetime.timestamp(date)))+"000000")
            jsonl["file_source"] = sys.argv[1]
            jsonl["file_generator"] = "Volutility netscan"
            #firehol
            if firehol:
                if not ipaddress.ip_address(d["ForeignAddr"]).is_private and d["ForeignAddr"] in firehol:
                    jsonl["tag"].append("Firehol")
                    if not 'firehol' in jsonl:
                        jsonl["firehol"] = []
                    jsonl["firehol"]+=firehol[d["ForeignAddr"]]
                    jsonl["firehol"]=list(set(jsonl["firehol"]))
            jsonl["tag"]=list(set(jsonl["tag"]))
            if jsonl:
                print("%s" % (json.dumps(jsonl)), file=fjsonl)
    except Exception as err:
        print("Error to open: /tmp/results/netscan.json"+" -- "+str(err))
        traceback.print_exc(file=sys.stdout)
with open("/tmp/results/yaranousedproc.json", encoding='utf-8') as fp:
    try:
        ds = json.load(fp)
        for d in ds:
            #write direct in jsonl
            jsonl = {"message": d['Rule']+' -- '+bytes.fromhex(d['Value'].replace('00','').replace(' ','')).decode('utf-8',"ignore"), "timestamp_desc": "Yara out of proc", "tag":['YaraFound']}
            jsonl["Yara_Rule"] = d["Rule"]
            jsonl["Yara_offset"] = str(d["Offset"])
            jsonl["Yara_ValueHex"] = d["Value"]
            jsonl["Yara_ValueAscii"] = bytes.fromhex(d['Value'].replace('00','').replace(' ','')).decode('utf-8',"ignore")
            date = now
            try:
                date = datetime.strptime(date_deb, "%Y-%m-%dT%H%M%S")
            except:
                date = now
            jsonl["timestamp"] = int(str(int(datetime.timestamp(date)))+"000000")
            jsonl["file_source"] = sys.argv[1]
            jsonl["file_generator"] = "Volutility Yara out of proc"
            if jsonl:
                print("%s" % (json.dumps(jsonl)), file=fjsonl)
    except Exception as err:
        print("Error to open: /tmp/results/yaranousedproc.json"+" -- "+str(err))
        traceback.print_exc(file=sys.stdout)
with open("/tmp/results/svcscan.json", encoding='utf-8') as fp:
    try:
        ds = json.load(fp)
        for d in ds:
            #write direct in jsonl
            msg=""
            if "Name" in d and d["Name"]:
                msg=d['Name']
            if "Display" in d and d["Display"]:
                msg+=' -- '+d['Display']
            if "Binary" in d and d["Binary"]:
                msg+=' -- '+d['Binary']
            jsonl = {"message": msg, "timestamp_desc": "Service", "tag": []}
            try:
                date = datetime.strptime(date_deb, "%Y-%m-%dT%H%M%S")
            except:
                date = now
            if "Pid" in d and d["Pid"]:
                if d["Pid"] in db:
                    if "From_Service" not in db[d["Pid"]]:
                        db[d["Pid"]]["From_Service"] = []
                    if d['Name'] not in db[d["Pid"]]["From_Service"]:
                        db[d["Pid"]]["From_Service"].append(d['Name'])
                    if 'Started_From_Service' not in db[d["Pid"]]["tag"]:
                        db[d["Pid"]]["tag"].append('Started_From_Service')
                    if 'ProcSuspect' in db[d["Pid"]]["tag"] or ('MalwareInfo' in db[d["Pid"]] and db[d["Pid"]]['MalwareInfo']):
                        jsonl["tag"].append('Linked_with_SuspectProc')
            if "Name" in d and d["Name"]:
                jsonl["Name"] = str(d["Name"])
                sidx=[]
                for ssid in serv_sid:
                    if ssid['Service'] == d["Name"]:
                        sidx.append(ssid['SID'])
                if sidx:
                    jsonl["SID"] = sidx
                if re.match(r"[bcdfghjklmnpqrstvwxz]{6}|[aeuoiy]{4}", d['Name'].lower()):
                    jsonl["tag"].append("ServiceSuspect")
            if "Display" in d and d["Display"]:
                jsonl["Description"] = str(d["Display"])
            if "Binary" in d and d["Binary"]:
                jsonl["cmdline"] = str(d["Binary"])
                for km,vm in db_mod.items():
                    if 'Driver Path' in vm and vm['Driver Path'] and d["Binary"] in vm['Driver Path']:
                        vm['tag'].append('Driver_in_Service')
                        if 'Driver_Link' not in jsonl:
                            jsonl['Driver_Link']=[]
                        jsonl['Driver_Link'].append(km)
                        if 'ModSuspect' in vm['tag'] or ('MalwareInfo' in vm and vm['MalwareInfo']):
                            jsonl["tag"].append('Linked_with_SuspectDriver')
                if re.match(r"[bcdfghjklmnpqrstvwxz]{5}|[aeuoiy]{4}", d['Binary'].lower()):
                    jsonl["tag"].append("ServiceSuspect")
                if "\\users\\" in d['Binary'].lower() or "\\appdata\\" in d['Binary'].lower():
                    jsonl["tag"].append("ServiceSuspect")
            if "Type" in d and d["Type"]:
                jsonl["Type"] = str(d["Type"])
            if "Start" in d and d["Start"]:
                jsonl["Start"] = str(d["Start"])
                if d["Start"] in ["SERVICE_BOOT_START", "SERVICE_DEMAND_START"]:
                    jsonl["tag"].append("Autorun")
            if "State" in d and d["State"]:
                jsonl["State"] = str(d["State"])
                if d["State"] == "SERVICE_RUNNING":
                    jsonl["tag"].append("Running")
            date = now
            jsonl["timestamp"] = int(str(int(datetime.timestamp(date)))+"000000")
            jsonl["file_source"] = sys.argv[1]
            jsonl["file_generator"] = "Volutility svcscan"
            jsonl["tag"]=list(set(jsonl["tag"]))
            if jsonl:
                print("%s" % (json.dumps(jsonl)), file=fjsonl)
    except Exception as err:
        print("Error to open: /tmp/results/svcscan.json"+" -- "+str(err))
        traceback.print_exc(file=sys.stdout)
#modx
for k,v in db_mod.items():
    jsonl = {"message": k, "timestamp_desc": "Module"}
    date = now
    try:
        if 'CreateTime' in v and v['CreateTime']:
            date = datetime.strptime(v['Createtime'], "%Y-%m-%dT%H%M%S")
        elif date_deb:
            date = datetime.strptime(date_deb, "%Y-%m-%dT%H%M%S")
    except:
        date = now
    jsonl['Path'] = str(k)
    for kx,vx in v.items():
        if kx == 'File':
            continue
        if isinstance(vx, int):
            jsonl[kx] = str(vx)
            continue
        jsonl[kx] = vx
    jsonl["timestamp"] = int(str(int(datetime.timestamp(date)))+"000000")
    jsonl["file_source"] = sys.argv[1]
    jsonl["file_generator"] = "Volutility modscan"
    jsonl["tag"]=list(set(jsonl["tag"]))
    if jsonl:
        print("%s" % (json.dumps(jsonl)), file=fjsonl)
#proc
for k,v in db.items():
    jsonl = {"message": 'PID: '+str(k)+' -- '+v['ImageFileName']+' -- '+v['cmdline'], "timestamp_desc": "Process"}
    date = now
    try:
        if 'CreateTime' in v and v['CreateTime']:
            date = datetime.strptime(v['Createtime'], "%Y-%m-%dT%H%M%S")
        elif date_deb:
            date = datetime.strptime(date_deb, "%Y-%m-%dT%H%M%S")
    except:
        date = now
    jsonl['PID'] = str(k)
    for kx,vx in v.items():
        if isinstance(vx, int):
            jsonl[kx] = str(vx)
            continue
        jsonl[kx] = vx
    jsonl["timestamp"] = int(str(int(datetime.timestamp(date)))+"000000")
    jsonl["file_source"] = sys.argv[1]
    jsonl["file_generator"] = "Volutility pscan"
    jsonl["tag"]=list(set(jsonl["tag"]))
    if jsonl:
        print("%s" % (json.dumps(jsonl)), file=fjsonl)
fjsonl.close()
