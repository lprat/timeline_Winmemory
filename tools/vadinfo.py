#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, sys
import shutil
import json
import subprocess
import pefile
test={}
if len(sys.argv) != 3:
    print("./changename.py path/proscan.json imgpath")
    sys.exit()
with open(sys.argv[1]) as fp:
    ds = json.load(fp)
    for d in ds:
        if "PAGE_EXECUTE_READWRITE" in d['Protection'] and not d['File']:
            print(str(d))
            if d['Process'] == "SBAMSvc.exe":
                continue
            if d['Start VPN'] == 0:
                continue
            process = subprocess.Popen(['python3', '/opt/tools/volatility3/vol.py', '-o', '/tmp/analyze/dumpvad/', '-r', 'json', '-f', sys.argv[2], 'windows.vadinfo.VadInfo', '--dump', '--pid', str(d['PID']), '--address', str(d['Start VPN'])],
                     stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            hex_string = format(d['Start VPN'], '#04x')
            hex_string2 = format(d['End VPN'], '#04x')
            process = subprocess.Popen(['/opt/tools/floss', '/tmp/analyze/dumpvad/pid.'+str(d['PID'])+'.vad.'+hex_string+'-'+hex_string2+'.dmp'],
                     stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE)
            stdout2, stderr2 = process.communicate()
            if stdout2:
                print("Floss for proc:"+str(d['PID']))
                with open('/tmp/analyze/dumpvad/pid.'+str(d['PID'])+'.vad.'+hex_string+'-'+hex_string2+'.floss', "wb") as text_file:
                    text_file.write(stdout2)
            #if PE -> use capa
            process = subprocess.Popen(['/opt/tools/capa', '/tmp/analyze/dumpvad/pid.'+str(d['PID'])+'.vad.'+hex_string+'-'+hex_string2+'.dmp'],
                     stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE)
            stdout2, stderr2 = process.communicate()
            if stdout2:
                print("Capa for proc:"+str(d['PID']))
                with open('/tmp/results/pid.'+str(d['PID'])+'.vad.'+hex_string+'-'+hex_string2+'.capa', "wb") as text_file:
                    text_file.write(stdout2)
            process = subprocess.Popen(['yara', '--print-strings', '/opt/rules/winapi.yar', '/opt/rules/capability.yar', '/opt/rules/com.yar', '/opt/rules/iid.yar', '/opt/rules/command.yar', '/tmp/analyze/dumpvad/pid.'+str(d['PID'])+'.vad.'+hex_string+'-'+hex_string2+'.floss'],
                     stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE)
            stdout2, stderr2 = process.communicate()
            if stdout2:
                print("Yara for proc:"+str(d['PID']))
                with open('/tmp/results/pid.'+str(d['PID'])+'.vad.'+hex_string+'-'+hex_string2+'.yarafound', "wb") as text_file:
                    text_file.write(stdout2)
            try:
                pe = pefile.PE('/tmp/analyze/dumpvad/pid.'+str(d['PID'])+'.vad.'+hex_string+'-'+hex_string2+'.dmp')
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
                if hasattr(pe, 'FileInfo'):
                    for fileinfo in pe.FileInfo:
                        fileinfo = fileinfo[0]
                        if fileinfo.Key == b'StringFileInfo':
                            for st in fileinfo.StringTable:
                                for entry in st.entries.items():
                                    files_info[entry[0].decode("ascii","ignore")] = entry[1].decode("ascii","ignore")
                if peimp:
                    files_info['PEImport']=peimp
                if peexp:
                    files_info['PEExport']=peexp
                print("PE info:\n"+str(files_info))
                if files_info:
                    with open('/tmp/results/pid.'+str(d['PID'])+'.vad.'+hex_string+'-'+hex_string2+'.peinfo', 'w') as json_file:
                        json.dump(files_info, json_file, indent=4, sort_keys=True)
            except pefile.PEFormatError as e:
                print("[-] PEFormatError: %s" % e.value)
            os.remove('/tmp/analyze/dumpvad/pid.'+str(d['PID'])+'.vad.'+hex_string+'-'+hex_string2+'.dmp')
            os.remove('/tmp/analyze/dumpvad/pid.'+str(d['PID'])+'.vad.'+hex_string+'-'+hex_string2+'.floss')
