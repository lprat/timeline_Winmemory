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
procx={}
procpid={}

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
        print("Error to open: /tmp/results/driverirp.json")
with open("/tmp/results/proc-sid.json", encoding='utf-8') as fp:
    try:
        procsid_tmp = json.load(fp)
        for item in items:
            if 'PID' in item and 'SID' in item and 'Name' in item:
                if item['pid'] not in procpid:
                    procpid[item['pid']] = {'names':[],'SID':[]}
                if item['Name'] not in procpid[item['pid']]['names']:
                    procpid[item['pid']]['names'].append(item['Name'])
                if item['SID'] not in procpid[item['pid']]['SID']:
                    procpid[item['pid']]['SID'].append(item['SID'])
    except Exception as err:
        print("Error to open: /tmp/results/proc-sid.json")
with open("/tmp/results/svcscan-sid.json", encoding='utf-8') as fp:
    try:
        serv_sid = json.load(fp)
    except Exception as err:
        print("Error to open: /tmp/results/svcscan-sid.json")
with open("/tmp/results/psscan.json", encoding='utf-8') as fp:
    try:
        ds = json.load(fp)
        for d in ds:
            if 'ImageFileName' in d and d['ImageFileName']:
                if d['ImageFileName'] not in procx:
                    procx[d['ImageFileName']]={'count': 0, 'rat': False, 'multisession': 0, 'PPID': [], 'msg':[]}
                procx[d['ImageFileName']]['count']+=1
                if d['ImageFileName'].lower() in ["svchost.exe", "powershell.exe", "regsvr32.exe", "bcdedit.exe", "mshta.exe", "schtasks.exe","wmic.exe", "cmd.exe", "rundll32.exe", "rar.exe", "at.exe",  "psexec", "psloggedon", "procdump", "psexec.exe", "psloggedon.exe", "procdump.exe", "winrm.vbs", "net.exe", "reg.exe", "sc.exe"]:
                    procx[d['ImageFileName']]['msg'].append('Legitime process can be used for dangerous activity')
                rats=['teamviewer','logmein','webex','mikogo','logicnow','ammyy','darkcomet','splashtop','vncviewer','tightvnc','winvnc']
                for rat in rats:
                    if rat in d['ImageFileName'].lower():
                        procx[d['ImageFileName']]['msg'].append('RAT tools in progress')
                        procx[d['ImageFileName']]['rat']=True
                if 'PPID' in d and d['PPID']:
                    for dp in ds:
                        if 'PID' in dp and dp['PID'] and d['PPID'] == dp['PID']:
                            if dp['ImageFileName'].lower() not in procx[d['ImageFileName']]['PPID']:
                                procx[d['ImageFileName']]['PPID'].append(dp['ImageFileName'].lower())
    except Exception as err:
        print("Error to open: /tmp/results/psscan.json")
#check suspect process based on SANS: https://www.sans.org/security-resources/posters/hunt-evil/165/download
for k,v in procx.items():
    if k.lower() == 'system':
        if v['count'] != 1:
            v['msg'].append('Number of '+k+' process > 1')
        if len(v['PPID']) != 0:
            v['msg'].append('Parent PID ('+' -- '.join(v['PPID'])+') on '+k+' process (should not exist)')
    elif k.lower() == 'wininit.exe':
        if v['count'] != 1:
            v['msg'].append('Number of '+k+' process > 1')
        if len(v['PPID']) != 0:
            v['msg'].append('Parent PID ('+' -- '.join(v['PPID'])+') on '+k+' process (should not exist)')
    elif k.lower() == 'winlogon.exe':
        if len(v['PPID']) != 0:
            v['msg'].append('Parent PID ('+' -- '.join(v['PPID'])+') on '+k+' process (should not exist)')
    elif k.lower() == 'csrss.exe':
        if len(v['PPID']) != 0:
            v['msg'].append('Parent PID ('+' -- '.join(v['PPID'])+') on '+k+' process (should not exist)')
        if v['count'] > 2:
            v['multisession'] = v['count']-1
            v['msg'].append(k+' process indicate you have '+str( v['count']-1)+' current sessions')
    elif k.lower() == 'services.exe':
        if v['count'] != 1:
            v['msg'].append('Number of '+k+' process > 1')
        if len(v['PPID']) != 1:
            v['msg'].append('Parent PID ('+' -- '.join(v['PPID'])+') on '+k+' process != 1')
        if 'wininit.exe' not in v['PPID']:
            v['msg'].append('Parent PID ('+' -- '.join(v['PPID'])+') on '+k+' process != wininit.exe')
    elif k.lower() == 'svhost.exe':
        if len(v['PPID']) != 1:
            v['msg'].append('Parent PID ('+' -- '.join(v['PPID'])+') on '+k+' process != 1')
        if 'wininit.exe' not in v['PPID']:
            v['msg'].append('Parent PID ('+' -- '.join(v['PPID'])+') on '+k+' process != services.exe')
    elif k.lower() == 'lsaiso.exe':
        if v['count'] != 1:
            v['msg'].append('Number of '+k+' process > 1')
        if len(v['PPID']) != 1:
            v['msg'].append('Parent PID ('+' -- '.join(v['PPID'])+') on '+k+' process != 1')
        if 'wininit.exe' not in v['PPID']:
            v['msg'].append('Parent PID ('+' -- '.join(v['PPID'])+') on '+k+' process != wininit.exe')
    elif k.lower() == 'lsm.exe':
        if v['count'] != 1:
            v['msg'].append('Number of '+k+' process > 1')
        if len(v['PPID']) != 1:
            v['msg'].append('Parent PID ('+' -- '.join(v['PPID'])+') on '+k+' process != 1')
        if 'wininit.exe' not in v['PPID']:
            v['msg'].append('Parent PID ('+' -- '.join(v['PPID'])+') on '+k+' process != wininit.exe')
    elif k.lower() == 'lsass.exe':
        if v['count'] != 1:
            v['msg'].append('Number of '+k+' process > 1')
        if len(v['PPID']) != 1:
            v['msg'].append('Parent PID ('+' -- '.join(v['PPID'])+') on '+k+' process != 1')
        if 'wininit.exe' not in v['PPID']:
            v['msg'].append('Parent PID ('+' -- '.join(v['PPID'])+') on '+k+' process != wininit.exe')
    elif k.lower() == 'explorer.exe':
        if len(v['PPID']) != 0:
            v['msg'].append('Parent PID ('+' -- '.join(v['PPID'])+') on '+k+' process (should not exist)')
        if v['count'] > 1:
            v['multisession'] = v['count']
            v['msg'].append(k+' process indicate you have '+str( v['count'])+' current sessions')

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
                                print("Error to open: "+'/tmp/results/'+fnamex+'.peinfo')
                    if os.path.isfile('/tmp/results/'+fnamex+'.impscan'):
                        if 'PeImpScan' not in db[pid]['tag']:
                            db[pid]['tag'].append('PeImpScan')
                        with open('/tmp/results/'+fnamex+'.impscan') as yfp:
                            try:
                                peimpscanx = json.load(yfp)
                                if 'PEImpScan' not in db[pid]:
                                    db[pid]['PEImpScan']=[]
                                db[pid]['PEImpScan'].append(str(peimpscanx))
                            except Exception as err:
                                print("Error to open: "+'/tmp/results/'+fnamex+'.impscan')
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
                        if 'File output' in d and d['File output'].endswith('.dmp'):
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
                                    speimp=peimp.split(" -> ")
                                    if len(speimp) == 2 and (re.match(r"[bcdfghjklmnpqrstvwxz]{5}", speimp[1].lower()) or re.match(r"[aeuoiy]{5}", speimp[1].lower())):
                                        files_info['PEImport'] = peimp
                                    else:
                                        files_info['PEImport'] = speimp[0]
                                    files_info['PEImport']=list(set(files_info['PEImport']))
                                if peexp:
                                    if 'PEExport' not in db[pid]:
                                        db[pid]['PEExport'] = []
                                    files_info['PEExport'] = peexp
                                    files_info['PEExport']=list(set(files_info['PEExport']))
                                if hasattr(pe, 'FileInfo'):
                                    for fileinfo in pe.FileInfo:
                                        fileinfo = fileinfo[0]
                                        if fileinfo.Key == b'StringFileInfo':
                                            for st in fileinfo.StringTable:
                                                for entry in st.entries.items():
                                                    files_info[entry[0].decode("ascii","ignore")] = entry[1].decode("ascii","ignore")
                                if files_info and suspect:
                                    if 'DllSuspect' not in db[pid]:
                                        db[pid]['DllSuspect'] = []
                                    db[pid]['DllSuspect'].append(d['Name']+'|'+str(files_info))
                                    if 'OriginalFilename' in files_info or 'InternalName' in files_info:
                                        samename=False
                                        if 'InternalName' in files_info and files_info['InternalName'].lower() == d['Name'].lower():
                                            samename=True
                                        elif 'OriginalFilename' in files_info and files_info['OriginalFilename'].lower() == d['Name'].lower():
                                            samename=True
                                        if not samename:
                                            if "DllPeNameDiff" not in db[pid]['tag']:
                                                db[pid]['tag'].append("DllPeNameDiff")
                                elif files_info:
                                    if 'DllInfo' not in db[pid]:
                                        db[pid]['DllInfo'] = []
                                    db[pid]['DllInfo'].append(d['Name']+'|'+str(files_info))
                                    if 'OriginalFilename' in files_info or 'InternalName' in files_info:
                                        samename=False
                                        if 'InternalName' in files_info and files_info['InternalName'].lower() == d['Name'].lower():
                                            samename=True
                                        elif 'OriginalFilename' in files_info and files_info['OriginalFilename'].lower() == d['Name'].lower():
                                            samename=True
                                        if not samename:
                                            if "DllPeNameDiff" not in db[pid]['tag']:
                                                db[pid]['tag'].append("DllPeNameDiff")
                                elif suspect:
                                    if 'DllSuspect' not in db[pid]:
                                        db[pid]['DllSuspect'] = []
                                    db[pid]['DllSuspect'].append(d['Name']+'|NotPeInfo')
                                else:
                                    if 'DllInfo' not in db[pid]:
                                        db[pid]['DllInfo'] = []
                                    db[pid]['DllInfo'].append(d['Name']+'|NotPeInfo')
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
                        if d['Type'] == 'Mutant' and "MutantUse" not in db[pid]['tag']:
                            db[pid]['tag'].append("MutantUse")
                    continue
                if v=='netscan':
                    if not "LISTENING" in d['State']:
                        if "NetUse" not in db[pid]['tag']:
                            db[pid]['tag'].append("NetUse")
                        if 'NetUse' not in db[pid]:
                            db[pid]['NetUse'] = []
                        nproto = 'unknown'
                        if d['Proto']:
                            nproto = str(d['Proto'])
                        nsrcip = 'unknown'
                        if d['LocalAddr']:
                            nsrcip = str(d['LocalAddr'])
                        nsrcport = 'unknown'
                        if d['LocalPort']:
                            nsrcport = str(d['LocalPort'])
                        ndstip = 'unknown'
                        if d['ForeignAddr']:
                            ndstip = str(d['ForeignAddr'])
                        ndstport = 'unknown'
                        if d['ForeignPort']:
                            ndstport = str(d['ForeignPort'])
                        nstate = 'unknown'
                        if d['State']:
                            nstate = str(d['State'])
                        if nproto+"|"+nsrcip+":"+nsrcport+"|"+ndstip+":"+ndstport+"|"+nstate not in db[pid]['NetUse']:
                            db[pid]['NetUse'].append(nproto+"|"+nsrcip+":"+nsrcport+"|"+ndstip+":"+ndstport+"|"+nstate)
                        if d['ForeignAddr'] and d['ForeignAddr'] != '*' and not ipaddress.ip_address(d["ForeignAddr"]).is_private and 'ImageFileName' in db[pid] and db[pid]['ImageFileName'].lower() in ['lsass.exe', 'system', 'svchost.exe']:
                            if "NetUseSuspect" not in db[pid]['tag']:
                                db[pid]['tag'].append("NetUseSuspect")
                        if d['ForeignAddr'] and d['ForeignAddr'] != '*' and d['LocalPort'] == 3389:
                            if "RDPinUse" not in db[pid]['tag']:
                                db[pid]['tag'].append("RDPinUse")
                    if "LISTENING" in d['State']:
                        if "NetUse" not in db[pid]['tag']:
                            db[pid]['tag'].append("NetUse")
                        if 'NetBind' not in db[pid]:
                            db[pid]['NetBind'] = []
                        if d['Proto']+"|"+d['LocalAddr']+":"+str(d['LocalPort']) not in db[pid]['NetBind']:
                            db[pid]['NetBind'].append(d['Proto']+"|"+d['LocalAddr']+":"+str(d['LocalPort']))
                    #firehol
                    if firehol:
                        if d["ForeignAddr"] and d["ForeignAddr"] != '*' and not ipaddress.ip_address(d["ForeignAddr"]).is_private and d["ForeignAddr"] in firehol:
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
                                speimp=peimp.split(" -> ")
                                if len(speimp) == 2 and (re.match(r"[bcdfghjklmnpqrstvwxz]{5}", speimp[1].lower()) or re.match(r"[aeuoiy]{5}", speimp[1].lower())):
                                    db[pid]['PEImport'] = peimp
                                else:
                                    db[pid]['PEImport'] = speimp[0]
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
                                if 'OriginalFilename' in files_info or 'InternalName' in files_info:
                                    samename=False
                                    if 'InternalName' in files_info and files_info['InternalName'].lower() == d['ImageFileName'].lower():
                                        samename=True
                                    elif 'OriginalFilename' in files_info and files_info['OriginalFilename'].lower() == d['ImageFileName'].lower():
                                        samename=True
                                    if not samename:
                                        if "PeNameDiff" not in db[pid]['tag']:
                                            db[pid]['tag'].append("PeNameDiff")
                                for kx,vx in files_info.items():
                                    if kx+"=="+vx not in db[pid]['PeInfo']:
                                        #TODO tag if internalname != ImageFileName | not microsoft
                                        db[pid]['PeInfo'].append(kx+"=="+vx)
                            else:
                                if "NotPeInfo" not in db[pid]['tag']:
                                    db[pid]['tag'].append("NotPeInfo")
                        except Exception as e:
                            print("[-] PEFormatError: %s" % str(e))
                if 'CreateTime' in d and d['CreateTime'] and 'CreateTime' not in db[pid]:
                    db[pid]['CreateTime'] = d['CreateTime']
                if 'ImageFileName' in d and d['ImageFileName'] and 'ImageFileName' not in db[pid]:
                    if d['ImageFileName'] in procx and len(procx[d['ImageFileName']]['PPID']) == 0:
                        if "ProcOrphan" not in db[pid]['tag']:
                            db[pid]['tag'].append("ProcOrphan")
                    if d['ImageFileName'] in procx and len(procx[d['ImageFileName']]['msg']) > 0:
                        if 'ProcLegalSuspect' not in db[pid]:
                            db[pid]['ProcLegalSuspect']=procx[d['ImageFileName']]['msg']
                        if "ProcLegalSuspect" not in db[pid]['tag']:
                            db[pid]['tag'].append("ProcLegalSuspect")
                        if procx[d['ImageFileName']]['rat'] and "RATinProgress" not in db[pid]['tag']:
                            db[pid]['tag'].append("RATinProgress")
                    db[pid]['ImageFileName'] = d['ImageFileName']
                if 'PPID' in d and d['PPID'] and 'PPID' not in db[pid]:
                    db[pid]['PPID'] = d['PPID']
                if 'SessionId' in d and d['SessionId'] and 'SessionId' not in db[pid]:
                    db[pid]['SessionId'] = d['SessionId']
                if 'Args' in d and d['Args'] and 'cmdline' not in db[pid]:
                    db[pid]['cmdline'] = d['Args']
                    if '://' in d['Args']:
                        if "ProcArgsURI" not in db[pid]['tag']:
                            db[pid]['tag'].append("ProcArgsURI")
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
            if d['Path'].lower().endswith('.sys') and '\\system32\\drivers\\' in d['Path'].lower():
                suspect=False
            elif d['Path'].lower().endswith('.dll') and '\\system32\\' in d['Path'].lower():
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
                    #keep suspect name (func or )
                    #keep
                    speimp=peimp.split(" -> ")
                    if len(speimp) == 2 and (re.match(r"[bcdfghjklmnpqrstvwxz]{5}", speimp[1].lower()) or re.match(r"[aeuoiy]{5}", speimp[1].lower())):
                        db_mod[d['Path']]['PEImport'] = peimp
                    else:
                        db_mod[d['Path']]['PEImport'] = speimp[0]
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
                    if 'OriginalFilename' in files_info or 'InternalName' in files_info:
                        samename=False
                        if 'InternalName' in files_info and files_info['InternalName'].lower() == d['Name'].lower():
                            samename=True
                        elif 'OriginalFilename' in files_info and files_info['OriginalFilename'].lower() == d['Name'].lower():
                            samename=True
                        if not samename:
                            if "PeNameDiff" not in db_mod[d['Path']]['tag']:
                                db_mod[d['Path']]['tag'].append("PeNameDiff")
                    for kx,vx in files_info.items():
                        if kx+"=="+vx not in db_mod[d['Path']]['PeInfo']:
                            #TODO tag if internalname != ImageFileName | not microsoft
                            db_mod[d['Path']]['PeInfo'].append(kx+"=="+vx)
                else:
                    if "NotPeInfo" not in db_mod[d['Path']]['tag']:
                        db_mod[d['Path']]['tag'].append("NotPeInfo")
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
            proto = 'unknown'
            if d['Proto']:
                proto = str(d['Proto'])
            srcip = 'unknown'
            if d['LocalAddr']:
                srcip = str(d['LocalAddr'])
            srcport = 'unknown'
            if d['LocalPort']:
                srcport = str(d['LocalPort'])
            dstip = 'unknown'
            if d['ForeignAddr']:
                dstip = str(d['ForeignAddr'])
            dstport = 'unknown'
            if d['ForeignPort']:
                dstport = str(d['ForeignPort'])
            state = 'unknown'
            if d['State']:
                state = str(d['State'])
            jsonl = {"message": '('+proto+')'+srcip+':'+srcport+'--'+state+'-->'+dstip+':'+dstport, "timestamp_desc": "Netstat", "tag":[]}
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
                if 'ForeignAddr' in d and d['ForeignAddr'] and d['ForeignAddr'] != '*' and d['LocalPort'] == 3389:
                    jsonl['tag'].append("RDPinUse")
            if "LocalPort" in d and d["LocalPort"]:
                jsonl["PORT_SRC"] = str(d["LocalPort"])
            if "Proto" in d and d["Proto"]:
                jsonl["Protocol"] = str(d["Proto"])
            if "State" in d and d["State"]:
                jsonl["State"] = str(d["State"])
            datex = now
            if "Created" in d and d["Created"]:
                # add date of file
                try:
                    datex = datetime.strptime(d["Created"], "%Y-%m-%dT%H%M%S") #2020-02-07T10:46:52
                except:
                    datex = now
                    jsonl["tag"].append("unknown_date")
            else:
                try:
                    datex = datetime.strptime(date_deb, "%Y-%m-%dT%H%M%S")
                except:
                    datex = now
                jsonl["tag"].append("unknown_date")
            #jsonl["timestamp"] = int(str(int(datetime.timestamp(date)))+"000000")
            jsonl["datetime"] = datex.strftime('%Y-%m-%dT%H:%M:%S.%f')
            jsonl["file_source"] = sys.argv[1]
            jsonl["file_generator"] = "Volutility netscan"
            #firehol
            if firehol:
                if d["ForeignAddr"] and d["ForeignAddr"] != '*' and not ipaddress.ip_address(d["ForeignAddr"]).is_private and d["ForeignAddr"] in firehol:
                    jsonl["tag"].append("Firehol")
                    if not 'firehol' in jsonl:
                        jsonl["firehol"] = []
                    jsonl["firehol"]+=firehol[d["ForeignAddr"]]
                    jsonl["firehol"]=list(set(jsonl["firehol"]))
            jsonl["tag"]=list(set(jsonl["tag"]))
            if not jsonl["tag"]:
                del jsonl["tag"]
            if jsonl:
                print("%s" % (json.dumps(jsonl)), file=fjsonl)
    except Exception as err:
        print("Error to open: /tmp/results/netscan.json"+" -- "+str(err))
        traceback.print_exc(file=sys.stdout)
with open("/tmp/results/filescan.json", encoding='utf-8') as fp:
    try:
        ds = json.load(fp)
        for d in ds:
            #write direct in jsonl
            ext=""
            filename=d['Name']
            try:
                filename=d['Name'].split('\\')[-1]
                ext=d['Name'].split('.')[-1]
            except:
                pass
            jsonl = {"message": d['Name'], "Path": d['Name'], "Filename": filename, "Extension": ext,  "timestamp_desc": "File in memory", "tag":[]}
            if '\\users\\' in d['Name'].lower() and ext.lower() in ['dll','jse','zip','ps1','exe','vbs','cmd','hta','sys','pif','scr','com','msi','msp','rar','ace','bat','jar','swf','jnlp','cpl']:
                jsonl["tag"].append('FileDangerous')
            if '\\users\\' in d['Name'].lower() and ext.lower() in ['rtf','doc','docx','pptx','ppt','xls','xlsx','otf','gadget','appref-ms','application','chm','scf','idx']:
                jsonl["tag"].append('FileSuspect')
            if "Offset" in d and d["Offset"]:
                jsonl["FileOffset"] = str(d["Offset"])
            datex = now
            if "Created" in d and d["Created"]:
                # add date of file
                try:
                    datex = datetime.strptime(d["Created"], "%Y-%m-%dT%H%M%S") #2020-02-07T10:46:52
                except:
                    datex = now
                    jsonl["tag"].append("unknown_date")
            else:
                try:
                    datex = datetime.strptime(date_deb, "%Y-%m-%dT%H%M%S")
                except:
                    datex = now
                jsonl["tag"].append("unknown_date")
            #jsonl["timestamp"] = int(str(int(datetime.timestamp(date)))+"000000")
            jsonl["datetime"] = datex.strftime('%Y-%m-%dT%H:%M:%S.%f')
            jsonl["file_source"] = sys.argv[1]
            jsonl["file_generator"] = "Volutility filescan"
            jsonl["tag"]=list(set(jsonl["tag"]))
            if not jsonl["tag"]:
                del jsonl["tag"]
            if jsonl:
                print("%s" % (json.dumps(jsonl)), file=fjsonl)
    except Exception as err:
        print("Error to open: /tmp/results/filescan.json"+" -- "+str(err))
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
            datex = now
            try:
                datex = datetime.strptime(date_deb, "%Y-%m-%dT%H%M%S")
            except:
                datex = now
            #jsonl["timestamp"] = int(str(int(datetime.timestamp(date)))+"000000")
            jsonl["datetime"] = datex.strftime('%Y-%m-%dT%H:%M:%S.%f')
            jsonl["file_source"] = sys.argv[1]
            jsonl["file_generator"] = "Volutility Yara out of proc"
            if not jsonl["tag"]:
                del jsonl["tag"]
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
            datex = now
            #jsonl["timestamp"] = int(str(int(datetime.timestamp(date)))+"000000")
            jsonl["datetime"] = datex.strftime('%Y-%m-%dT%H:%M:%S.%f')
            jsonl["file_source"] = sys.argv[1]
            jsonl["file_generator"] = "Volutility svcscan"
            jsonl["tag"]=list(set(jsonl["tag"]))
            if not jsonl["tag"]:
                del jsonl["tag"]
            if jsonl:
                print("%s" % (json.dumps(jsonl)), file=fjsonl)
    except Exception as err:
        print("Error to open: /tmp/results/svcscan.json"+" -- "+str(err))
        traceback.print_exc(file=sys.stdout)
#modx
for k,v in db_mod.items():
    jsonl = {"message": k, "timestamp_desc": "Module"}
    datex = now
    try:
        if 'CreateTime' in v and v['CreateTime']:
            datex = datetime.strptime(v['Createtime'], "%Y-%m-%dT%H%M%S")
        elif date_deb:
            datex = datetime.strptime(date_deb, "%Y-%m-%dT%H%M%S")
    except:
        datex = now
    jsonl['Path'] = str(k)
    for kx,vx in v.items():
        if kx == 'File':
            continue
        if isinstance(vx, int):
            jsonl[kx] = str(vx)
            continue
        jsonl[kx] = vx
    #jsonl["timestamp"] = int(str(int(datetime.timestamp(date)))+"000000")
    jsonl["datetime"] = datex.strftime('%Y-%m-%dT%H:%M:%S.%f')
    jsonl["file_source"] = sys.argv[1]
    jsonl["file_generator"] = "Volutility modscan"
    jsonl["tag"]=list(set(jsonl["tag"]))
    if not jsonl["tag"]:
        del jsonl["tag"]
    if jsonl:
        print("%s" % (json.dumps(jsonl)), file=fjsonl)
#proc
for k,v in db.items():
    msg='PID: '+str(k)
    if 'ImageFileName' in v and v['ImageFileName']:
        msg+=' -- '+v['ImageFileName']
    if 'cmdline' in v and v['cmdline']:
        msg+=' -- '+v['cmdline']
    jsonl = {"message": msg, "timestamp_desc": "Process"}
    datex = now
    try:
        if 'CreateTime' in v and v['CreateTime']:
            datex = datetime.strptime(v['Createtime'], "%Y-%m-%dT%H%M%S")
        elif date_deb:
            datex = datetime.strptime(date_deb, "%Y-%m-%dT%H%M%S")
    except:
        datex = now
    jsonl['PID'] = str(k)
    for kx,vx in v.items():
        if isinstance(vx, int):
            jsonl[kx] = str(vx)
            continue
        jsonl[kx] = vx
    if jsonl['PID'] in procpid:
        jsonl['SID_names']=procpid[item['pid']]['names']
        jsonl['SIDs']=procpid[item['pid']]['SID']
    #jsonl["timestamp"] = int(str(int(datetime.timestamp(date)))+"000000")
    jsonl["datetime"] = datex.strftime('%Y-%m-%dT%H:%M:%S.%f')
    jsonl["file_source"] = sys.argv[1]
    jsonl["file_generator"] = "Volutility pscan"
    jsonl["tag"]=list(set(jsonl["tag"]))
    if not jsonl["tag"]:
        del jsonl["tag"]
    if jsonl:
        print("%s" % (json.dumps(jsonl)), file=fjsonl)
fjsonl.close()
