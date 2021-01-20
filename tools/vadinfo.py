#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#Author: Lionel PRAT lionel.prat9@gmail.com
import os, sys
import shutil
import json
import subprocess
import pefile
import distorm3
import struct
import binascii
import traceback

def _ascii_bytes(bytes):
    """Converts bytes into an ascii string"""
    return "".join([chr(x) if 32 < x < 127 else '.' for x in binascii.unhexlify(bytes)])
def _display_data(remaining_data: bytes, format_string: str = "B", ascii: bool = True):
    """Display a series of bytes"""
    chunk_size = struct.calcsize(format_string)
    data_length = len(remaining_data)
    remaining_data = remaining_data[:data_length - (data_length % chunk_size)]

    while remaining_data:
        current_line, remaining_data = remaining_data[:16], remaining_data[16:]

        data_blocks = [current_line[chunk_size * i:chunk_size * (i + 1)] for i in range(16 // chunk_size)]
        data_blocks = [x for x in data_blocks if x != b'']
        valid_data = [("{:0" + str(2 * chunk_size) + "x}").format(struct.unpack(format_string, x)[0])
                      for x in data_blocks]
        return valid_data[0]

def get_addr(fpath, offset, size=16):
    fo = open(fpath, "rb")
    fo.seek(offset, 0)
    data=fo.read(size)
    fo.close()
    addr=_display_data(data, format_string = "I")
    return addr

def _call_or_unc_jmp(op):
    return ((op.flowControl == 'FC_CALL' and
            op.mnemonic == "CALL") or
            (op.flowControl == 'FC_UNC_BRANCH' and
            op.mnemonic == "JMP"))

if len(sys.argv) != 3:
    print("./vadinfo.py path/vadinfo.json imgpath")
    sys.exit()

modules={}
dlllist={}
filex={}
exports={}

with open("/tmp/results/listfiles.json", encoding='utf-8') as fp:
    try:
        filex = json.load(fp)
    except Exception as err:
        print("Error to open: /tmp/results/listfiles.json")

with open('/tmp/results/dlllist.json', encoding='utf-8') as fp:
    try:
        ds = json.load(fp)
        for d in ds:
            pid=d['PID']
            if pid not in dlllist:
                dlllist[pid]={}
            if 'Path' in d and d['Path'] and 'File output' in d and d['File output'].endswith('.dmp'):
                #    if d['Path'] not in dlllist[pid]:
                #        dlllist[pid][d['Path']]={'base':d['Base'], 'File output': filex['pa'][d['File output']]}
                if d['Base'] not in dlllist[pid]:
                    dlllist[pid][d['Base']]={'Path':d['Path'], 'File output': filex['pa'][d['File output']]}
                else:
                    print('Error base already exist')
    except Exception as err:
        print("Error to open: /tmp/results/dlllist.json"+" -- "+str(err))
        traceback.print_exc(file=sys.stdout)

with open(sys.argv[1]) as fp:
    ds = json.load(fp)
    #create modules
    for d in ds:
        pid=d['PID']
        if pid not in modules:
            modules[pid]={}
        if pid in dlllist and 'File' in d and d['File'] and d['Start VPN'] in dlllist[pid]:
            modules[pid][d['File']]={'vstart':d['Start VPN'],'vend':d['End VPN'],'File output':dlllist[pid][d['Start VPN']]['File output']}
        elif 'File' in d and d['File']:
            #indicate DLL used and number of func
            modules[pid][d['File']]={'vstart':d['Start VPN'],'vend':d['End VPN']}
    for d in ds:
        if d['Process'] == 'conhost.exe' and "READWRITE" in d['Protection'] and not d['File'] and d['Start VPN'] != 0:
            #check command history - strings -t d -e l *.dmp >> conhost.uni (Idea From SANS)
            print("Extract info from conhost.exe")
            process = subprocess.Popen(['python3', '/opt/tools/volatility3/vol.py', '-o', '/tmp/analyze/dumpcon/', '-r', 'json', '-f', sys.argv[2], 'windows.vadinfo.VadInfo', '--dump', '--pid', str(d['PID']), '--address', str(d['Start VPN'])],
                     stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            hex_string = format(d['Start VPN'], '#04x')
            hex_string2 = format(d['End VPN'], '#04x')
            process = subprocess.Popen(['/opt/tools/floss', '/tmp/analyze/dumpcon/pid.'+str(d['PID'])+'.vad.'+hex_string+'-'+hex_string2+'.dmp'],
                     stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE)
            stdout2, stderr2 = process.communicate()
            if stdout2:
                print("Floss for proc:"+str(d['PID']))
                with open('/tmp/analyze/dumpcon/pid.'+str(d['PID'])+'.vad.'+hex_string+'-'+hex_string2+'.floss', "wb") as text_file:
                    text_file.write(stdout2)
            process = subprocess.Popen(['strings', '-t', 'd', '-e', 'l', '/tmp/analyze/dumpcon/pid.'+str(d['PID'])+'.vad.'+hex_string+'-'+hex_string2+'.dmp'],
                     stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE)
            stdout2, stderr2 = process.communicate()
            if stdout2:
                print("Strings for proc:"+str(d['PID']))
                with open('/tmp/analyze/dumpcon/pid.'+str(d['PID'])+'.vad.'+hex_string+'-'+hex_string2+'.uni', "wb") as text_file:
                    text_file.write(stdout2)
            process = subprocess.Popen(['cat', '/tmp/analyze/dumpcon/*.floss', '>', '/tmp/results/conhost-data.floss'],
                     stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE)
            stdout2, stderr2 = process.communicate()
            process = subprocess.Popen(['cat', '/tmp/analyze/dumpcon/*.uni', '>', '/tmp/results/conhost-data.uni'],
                     stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE)
            stdout2, stderr2 = process.communicate()
            shutil.rmtree('/tmp/analyze/dumpcon/')
        if "PAGE_EXECUTE_READWRITE" in d['Protection'] and not d['File']:
            print(str(d))
            iat_ptr={}
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
            process = subprocess.Popen(['objdump' ,'-x' ,'-D' ,'/tmp/analyze/dumpvad/pid.'+str(d['PID'])+'.vad.'+hex_string+'-'+hex_string2+'.dmp'],
                     stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE)
            stdout2, stderr2 = process.communicate()
            if stdout2:
                print("ObjDump for proc:"+str(d['PID']))
                with open('/tmp/results/pid.'+str(d['PID'])+'.vad.'+hex_string+'-'+hex_string2+'.objdump', "wb") as text_file:
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
                #IMPSCAN
                impscan={}
                if hasattr(pe, 'FILE_HEADER') and hasattr(pe, 'OPTIONAL_HEADER'):
                    mode=None
                    modeadr=32
                    memory_model = '64bit'
                    iat_ptr={}
                    reg_redirect = {"RAX":0x0, "RBX":0x0, "RCX":0x0, "RDX":0x0}
                    if hex(pe.FILE_HEADER.Machine) == '0x14c':
                        mode = distorm3.Decode32Bits
                        memory_model = '32bit'
                        modeadr=16
                        reg_redirect = {"EAX":0x0, "EBX":0x0, "ECX":0x0, "EDX":0x0}
                        #print("This is a 32-bit binary")
                    else:
                        mode = distorm3.Decode64Bits
                        #print("This is a 64-bit binary")
                    offset = pe.OPTIONAL_HEADER.AddressOfEntryPoint
                    base_address=d['Start VPN']
                    end_address=d['End VPN']
                    for op in distorm3.DecomposeGenerator(offset, pe.get_memory_mapped_image(), mode):
                        if not op.valid:
                            continue
                        iat_loc = None
                        if memory_model == '32bit':
                            if (_call_or_unc_jmp(op) and
                                op.operands[0].type == 'AbsoluteMemoryAddress'):
                                iat_loc = (op.operands[0].disp) & 0xffffffff
                            if op.mnemonic == "MOV" and op.operands[0].type == 'Register' and op.operands[1].type == 'AbsoluteMemoryAddress':
                                reg_redirect[str(op.operands[0])] =op.operands[1].disp
                            if op.mnemonic == "CALL" and op.operands[0].type == 'Register':
                                iat_loc = reg_redirect[str(op.operands[0])]
                        else:
                            if (_call_or_unc_jmp(op) and
                                'FLAG_RIP_RELATIVE' in op.flags and
                                op.operands[0].type == 'AbsoluteMemory'):
                                iat_loc = op.address + op.size + op.operands[0].disp
                            #TODO fix iat on register 64b
                            if op.mnemonic == "MOV" and op.operands[0].type == 'Register' and op.operands[1].type == 'AbsoluteMemoryAddress':
                                reg_redirect[str(op.operands[0])] =op.operands[1].disp
                            if op.mnemonic == "CALL" and op.operands[0].type == 'Register':
                                iat_loc = reg_redirect[str(op.operands[0])]
                        if (not iat_loc or
                            (iat_loc < base_address) or
                            (iat_loc > end_address)):
                            continue
                        addr=get_addr('/tmp/analyze/dumpvad/pid.'+str(d['PID'])+'.vad.'+hex_string+'-'+hex_string2+'.dmp',iat_loc-base_address,modeadr)
                        if iat_loc not in iat_ptr:
                            iat_ptr[iat_loc]=int(addr, 16)
                        elif int(addr, 16) != iat_ptr[iat_loc]:
                            print("DEBUG error IAT 0x%08x -> 0x%08x vs 0x%08x" % (iat_loc, addr, iat_ptr[iat_loc]))
                    #list func
                    if iat_ptr and d['PID'] in modules and modules[d['PID']]:
                        if d['PID'] not in exports:
                            exports[d['PID']]={}
                            for kmx,vmx in modules[d['PID']].items():
                                #kmx = path DLL
                                if 'File output' in vmx:
                                    try:
                                        dll=pefile.PE(vmx['File output'])
                                        if hasattr(dll, 'DIRECTORY_ENTRY_EXPORT'):
                                            for exp in dll.DIRECTORY_ENTRY_EXPORT.symbols:
                                                if exp.name and exp.address:
                                                    adrx=exp.address+vmx['vstart']
                                                    namedll=None
                                                    try:
                                                        namedll=kmx.split('\\')[-1]
                                                    except:
                                                        namedll=kmx
                                                    exports[d['PID']][adrx]={'func':exp.name.decode(errors='replace'), 'dll':namedll}
                                    except Exception as err:
                                        print('Error to open dll('+vmx['File output']+'):'+str(err))
                    for k,v in iat_ptr.items():
                        #print("IAT 0x%08x -> 0x%08x" % (k, v))
                        if d['PID'] in exports and exports[d['PID']] and v in exports[d['PID']]:
                            #Func found
                            impscan[v]=exports[d['PID']][v]
                        elif d['PID'] in modules and modules[d['PID']]:
                            for kmx,vmx in modules[d['PID']].items():
                                #kmw = path DLL
                                if vmx['vstart'] <= v <= vmx['vend']:
                                    #Ok dll found, but not found function
                                    #command: "objdump -x -D"
                                    namedll=None
                                    try:
                                        namedll=kmx.split('\\')[-1]
                                    except:
                                        namedll=kmx
                                    madr="0x%0.2X" % (v-vmx['vstart'])
                                    impscan[v]={'func':'Not found at '+madr, 'dll':namedll}
                if peimp:
                    files_info['PEImport']=peimp
                if peexp:
                    files_info['PEExport']=peexp
                if impscan:
                    with open('/tmp/results/pid.'+str(d['PID'])+'.vad.'+hex_string+'-'+hex_string2+'.impscan', 'w') as json_file:
                        json.dump(impscan, json_file, indent=4, sort_keys=True)
                #print("PE info:\n"+str(files_info))
                if files_info:
                    with open('/tmp/results/pid.'+str(d['PID'])+'.vad.'+hex_string+'-'+hex_string2+'.peinfo', 'w') as json_file:
                        json.dump(files_info, json_file, indent=4, sort_keys=True)
            except pefile.PEFormatError as e:
                print("[-] PEFormatError: %s" % e.value)
            os.remove('/tmp/analyze/dumpvad/pid.'+str(d['PID'])+'.vad.'+hex_string+'-'+hex_string2+'.dmp')
            os.remove('/tmp/analyze/dumpvad/pid.'+str(d['PID'])+'.vad.'+hex_string+'-'+hex_string2+'.floss')
