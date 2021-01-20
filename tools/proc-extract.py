#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, sys
import shutil
import json
import subprocess
import pefile

if len(sys.argv) != 4:
    print("./proc_ana.py path/vadinfo.json imgpath pid")
    sys.exit()
with open(sys.argv[1]) as fp:
    ds = json.load(fp)
    for d in ds:
        if d['PID'] != int(sys.argv[3]):
            continue
        if not os.path.isdir('/tmp/analyze/'+str(d['PID'])):
            os.mkdir('/tmp/analyze/'+str(d['PID']))
        pathx='/tmp/analyze/'+str(d['PID'])+'/'
        if ("PAGE_EXECUTE_READWRITE" in d['Protection'] or "PAGE_READWRITE" in d['Protection']) and not d['File']:
            print(str(d))
            if d['Start VPN'] == 0:
                continue
            process = subprocess.Popen(['python3', '/opt/tools/volatility3/vol.py', '-o', pathx, '-r', 'json', '-f', sys.argv[2], 'windows.vadinfo.VadInfo', '--dump', '--pid', str(d['PID']), '--address', str(d['Start VPN'])],
                     stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            hex_string = format(d['Start VPN'], '#04x')
            hex_string2 = format(d['End VPN'], '#04x')
            process = subprocess.Popen(['/opt/tools/floss', pathx+'pid.'+str(d['PID'])+'.vad.'+hex_string+'-'+hex_string2+'.dmp'],
                     stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE)
            stdout2, stderr2 = process.communicate()
            if stdout2:
                print("Floss for proc:"+str(d['PID']))
                with open(pathx+'pid.'+str(d['PID'])+'.vad.'+hex_string+'-'+hex_string2+'.floss', "wb") as text_file:
                    text_file.write(stdout2)
            #if PE -> use capa
            process = subprocess.Popen(['/opt/tools/capa', pathx+'pid.'+str(d['PID'])+'.vad.'+hex_string+'-'+hex_string2+'.dmp'],
                     stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE)
            stdout2, stderr2 = process.communicate()
            if stdout2:
                print("Capa for proc:"+str(d['PID']))
                with open(pathx+'pid.'+str(d['PID'])+'.vad.'+hex_string+'-'+hex_string2+'.capa', "wb") as text_file:
                    text_file.write(stdout2)
            process = subprocess.Popen(['yara', '--print-strings', '/opt/rules/winapi.yar', '/opt/rules/capability.yar', '/opt/rules/com.yar', '/opt/rules/iid.yar', '/opt/rules/command.yar', pathx+'pid.'+str(d['PID'])+'.vad.'+hex_string+'-'+hex_string2+'.dmp'],
                     stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE)
            stdout2, stderr2 = process.communicate()
            if stdout2:
                print("Yara for proc:"+str(d['PID']))
                with open('/tmp/results/pid.'+str(d['PID'])+'.vad.'+hex_string+'-'+hex_string2+'.yarafound', "wb") as text_file:
                    text_file.write(stdout2)
            process = subprocess.Popen(['objdump' ,'-x' ,'-D' ,pathx+'pid.'+str(d['PID'])+'.vad.'+hex_string+'-'+hex_string2+'.dmp'],
                     stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE)
            stdout2, stderr2 = process.communicate()
            if stdout2:
                print("ObjDump for proc:"+str(d['PID']))
                with open('/tmp/results/pid.'+str(d['PID'])+'.vad.'+hex_string+'-'+hex_string2+'.objdump', "wb") as text_file:
                    text_file.write(stdout2)
            try:
                pe = pefile.PE(pathx+'pid.'+str(d['PID'])+'.vad.'+hex_string+'-'+hex_string2+'.dmp')
                files_info = {}
                if hasattr(pe, 'FileInfo'):
                    for fileinfo in pe.FileInfo:
                        fileinfo = fileinfo[0]
                        if fileinfo.Key == b'StringFileInfo':
                            for st in fileinfo.StringTable:
                                for entry in st.entries.items():
                                    files_info[entry[0].decode("ascii","ignore")] = entry[1].decode("ascii","ignore")
                print("PE info:\n"+str(files_info))
                if files_info:
                    with open('/tmp/results/pid.'+str(d['PID'])+'.vad.'+hex_string+'-'+hex_string2+'.peinfo', 'w') as json_file:
                        json.dump(files_info, json_file, indent=4, sort_keys=True)
            except pefile.PEFormatError as e:
                print("[-] PEFormatError: %s" % e.value)
            os.remove(pathx+'pid.'+str(d['PID'])+'.vad.'+hex_string+'-'+hex_string2+'.dmp')
            #os.remove(pathx+'pid.'+str(d['PID'])+'.vad.'+hex_string+'-'+hex_string2+'.floss')
