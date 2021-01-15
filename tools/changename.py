#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, sys
import shutil
import json
filez={'pi':{},'pa':{}}
modulez={'fn':{},'pa':{}}
test={}
if len(sys.argv) != 3:
    print("./changename.py path/proscan.json dumpdir/")
    sys.exit()
with open(sys.argv[1]) as fp:
    ds = json.load(fp)
    for d in ds:
        if "File output" in d and d["File output"] != "Error outputting file" and "ImageFileName" in d:
            test[d["File output"]]=d['ImageFileName']
for root, directories, filenames in os.walk(sys.argv[2]):
    for filename in filenames:
        filex = os.path.join(root, filename)
        fx=filename.split(".")
        i=0
        f=0
        for ext in fx:
            if ext.startswith("0x"):
                f=i-1
                break
            i+=1
        namex=fx[f-1]+"."+fx[f]
        filedst=os.path.join(root, namex)
        pid=None
        if namex.startswith("pid"):
            if filename in test and test[filename]:
                namex=test[filename]
        if filename.startswith("pid"):
            pid=int(fx[1])
        namex=namex.lower()
        if not (namex.endswith(".exe") or namex.endswith(".dll") or namex.endswith(".sys")):
            namex+=".exe"
        filedst=os.path.join(root, namex)
        if os.path.isfile(filedst):
            #mv in dir timestamp
            os.mkdir(filex[:-4])
            shutil.move(filex,os.path.join(filex[:-4], namex))
            if pid:
                filez['pi'][os.path.join(filex[:-4], namex)]=pid
                filez['pa'][filename]=os.path.join(filex[:-4], namex)
            else:
                modulez['fn'][os.path.join(filex[:-4], namex)]=filename
                modulez['pa'][filename]=os.path.join(filex[:-4], namex)
            print("Mv file:"+filex+" -> " +os.path.join(filex[:-4], namex))
        else:
            #mv
            filedst=os.path.join(root, namex)
            shutil.move(filex,filedst)
            if pid:
                filez['pi'][filedst]=pid
                filez['pa'][filename]=filedst
            else:
                modulez['fn'][filedst]=filename
                modulez['pa'][filename]=filedst
            print("Mv file:"+filex+" -> " +filedst)
if filez:
    with open('/tmp/results/listfiles.json', 'w') as json_file:
        json.dump(filez, json_file, indent=4, sort_keys=True)
if modulez:
    with open('/tmp/results/listmodules.json', 'w') as json_file:
        json.dump(modulez, json_file, indent=4, sort_keys=True)
