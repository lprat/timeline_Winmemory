#!/bin/bash
## Analyze memory image to create timeline oriented malware search
if [ $# -eq 0 ]
  then
    echo "./script img [timeout]"
    exit -1
fi

#adapt time according by size of image
FILESIZE=$(stat -c%s "$1")
TSZ=$(($FILESIZE/17894604))
timestop="${TSZ}m"
if [[ -n $2 ]]; then
  timestop=$2
fi

###Loki install and updates###
lokiinstall(){
	pushd /opt/tools
	git clone --recursive https://github.com/Neo23x0/Loki.git
  cd  /opt/tools/Loki
	pip2 install -r requirements.txt
	python /opt/tools/Loki/loki-upgrader.py
	#git clone https://github.com/Neo23x0/signature-base
  popd
}
lokiupdate(){
	pushd /opt/tools/Loki
	git pull --recursive
	python /opt/tools/Loki/loki-upgrader.py
	popd
}

#volatility update
vol3update(){
	pushd /opt/tools
  mv volatility3 volatility3.old
  git clone https://github.com/volatilityfoundation/volatility3 && \
  pip3 install -U capstone pefile yara-python && \
  patch -i /tmp/patchvol3_nofail /opt/tools/volatility3/volatility3/cli/__init__.py && \
  patch -i /tmp/patchvol3_nofail2 /opt/tools/volatility3/volatility3/cli/text_renderer.py && \
  patch -i /tmp/patchvol3_nofail3 /opt/tools/volatility3/volatility3/framework/constants/__init__.py && \
  patch -i /tmp/patchvol3 /opt/tools/volatility3/volatility3/cli/text_renderer.py && \
  patch -i /tmp/patchvol3_dll /opt/tools/volatility3/volatility3/framework/plugins/windows/dlllist.py && \
  touch /tmp/patch_ok
  if [ ! -f /tmp/patch_ok ]; then
    echo "Patch error get old version"
    rm -rf volatility3
    mv volatility3.old volatility3
  else
    rm /tmp/patch_ok
    rm -rf volatility3.old
  fi
  cd /opt/tools/volatility3/volatility3/symbols/
  curl -fL https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip -o linux.zip     && \
  unzip linux.zip                                                                                    && \
  curl -fL https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip -o mac.zip         && \
  unzip mac.zip                                                                                      && \
  curl -fL https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip -o windows.zip && \
  unzip windows.zip
	popd
}

###capa && floss install###
flossinstall(){
	pushd /opt/tools
	wget https://s3.amazonaws.com/build-artifacts.floss.flare.fireeye.com/travis/linux/dist/floss -O /opt/tools/floss
	chmod +x  /opt/tools/floss
    popd
}
capainstall(){
	pushd /opt/tools
	curl -s https://api.github.com/repos/mandiant/capa/releases/latest \
   | grep "http.*capa.*linux.zip" \
   | cut -d : -f 2,3 \
   | tr -d \" \
   | wget -q -O /opt/tools/capa.zip -i -
   unzip /opt/tools/capa.zip
   chmod +x  /opt/tools/capa
    popd
}


###yara mem rules###
yarathorinstall(){
 pushd /opt/tools
 wget https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/thor-hacktools.yar -O /opt/rules/thor-hacktools.yar
 popd
}

yaraiddqdinstall(){
 pushd /opt/tools
 wget https://gist.githubusercontent.com/Neo23x0/f1bb645a4f715cb499150c5a14d82b44/raw/d621fcfd496d03dca78f9ff390cad88684139d64/iddqd.yar -O /opt/tools/Loki/signature-base/yara/iddqd.yar
 popd
}

lokimalinstall(){
 pushd /opt/tools
 wget https://raw.githubusercontent.com/JPCERTCC/MalConfScan/master/yara/rule.yara -O /opt/tools/Loki/signature-base/yara/malconfscan.yar
 cp /opt/tools/Loki/signature-base/yara/malconfscan.yar /opt/rules/
 popd
}

vol3update
freshclam


if [[ -e /opt/tools/Loki ]]; then
	lokiupdate
else
	lokiinstall
fi

if [[ -f /opt/tools/floss ]];then
	echo -e "Floss installed"
else
	flossinstall
fi

if [[ -f /opt/tools/capa ]];then
	echo -e "Capa installed"
else
	capainstall
fi

if [[ -f /opt/rules/thor-hacktools.yar ]];then
	echo -e "Rules thor-hacktools.yar installed"
else
	yarathorinstall
fi

if [[ -f /opt/tools/Loki/signature-base/yara/malconfscan.yar ]];then
	echo -e "Rules malconfscan.yar installed"
else
	lokimalinstall
fi

if [[ -f /opt/tools/Loki/signature-base/yara/iddqd.yar ]];then
	echo -e "Rules iddqd.yar installed"
else
	yaraiddqdinstall
fi

echo -e "OK, start memory scan!"
mkdir -p /tmp/analyze/dump
mkdir -p /tmp/analyze/dump-yara
mkdir -p /tmp/results

timeout -v $timestop python3 /opt/tools/volatility3/vol.py -q -f $1 -r json windows.vadinfo.VadInfo > /tmp/results/vadinfo.json 2> /tmp/results/vadinfo.err
if [ $? -eq 1 ]
then
  timeout -v $timestop python3 /opt/tools/volatility3/vol.py -q --no-fail -f $1 -r json windows.vadinfo.VadInfo > /tmp/results/vadinfo.json 2> /tmp/results/vadinfo2.err
fi
{
timeout -v $timestop python3 /opt/tools/volatility3/vol.py -q -f $1 -r json windows.netscan.NetScan > /tmp/results/netscan.json  2> /tmp/results/netscan.err
if [ $? -eq 1 ]
then
  timeout -v $timestop python3 /opt/tools/volatility3/vol.py -q --no-fail -f $1 -r json windows.netscan.NetScan > /tmp/results/netscan.json  2> /tmp/results/netscan2.err
fi
} &
{
timeout -v $timestop python3 /opt/tools/volatility3/vol.py -q -f $1 -r json windows.filescan.FileScan > /tmp/results/filescan.json 2> /tmp/results/filescan.err
if [ $? -eq 1 ]
then
  timeout -v $timestop python3 /opt/tools/volatility3/vol.py -q --no-fail -f $1 -r json windows.filescan.FileScan > /tmp/results/filescan.json 2> /tmp/results/filescan2.err
fi
}&
{
timeout -v $timestop python3 /opt/tools/volatility3/vol.py -q -f $1 -r json windows.svcscan > /tmp/results/svcscan.json 2> /tmp/results/vcscan.err
if [ $? -eq 1 ]
then
  timeout -v $timestop python3 /opt/tools/volatility3/vol.py -q --no-fail -f $1 -r json windows.svcscan > /tmp/results/svcscan.json 2> /tmp/results/vcscan2.err
fi
}&
{
timeout -v $timestop python3 /opt/tools/volatility3/vol.py -q -f $1 -r json windows.getservicesids.GetServiceSIDs > /tmp/results/svcscan-sid.json 2> /tmp/results/svcscan-sid.err
if [ $? -eq 1 ]
then
  timeout -v $timestop python3 /opt/tools/volatility3/vol.py -q --no-fail -f $1 -r json windows.getservicesids.GetServiceSIDs > /tmp/results/svcscan-sid.json 2> /tmp/results/svcscan-sid2.err
fi
}&
{
timeout -v $timestop python3 /opt/tools/volatility3/vol.py -q -f $1 -r json windows.getsids.GetSIDs > /tmp/results/proc-sid.json 2> /tmp/results/proc-sid.err
if [ $? -eq 1 ]
then
  timeout -v $timestop python3 /opt/tools/volatility3/vol.py -q --no-fail -f $1 -r json windows.getsids.GetSIDs > /tmp/results/proc-sid.json 2> /tmp/results/proc-sid2.err
fi
}&
#timeout $timestop python3 /opt/tools/volatility3/vol.py -q -f $1 windows.pstree.PsTree > /tmp/results/pstree.json 2> /tmp/results/pstree.err &
{
timeout -v $timestop python3 /opt/tools/volatility3/vol.py -q -f $1 -r json windows.envars.Envars > /tmp/results/env.json 2> /tmp/results/env.err
if [ $? -eq 1 ]
then
  timeout -v $timestop python3 /opt/tools/volatility3/vol.py -q --no-fail -f $1 -r json windows.envars.Envars > /tmp/results/env.json 2> /tmp/results/env2.err
fi
}&
{
timeout -v $timestop python3 /opt/tools/volatility3/vol.py -q -f $1 -r json windows.handles.Handles > /tmp/results/handle.json 2> /tmp/results/handle.err
if [ $? -eq 1 ]
then
  timeout -v $timestop python3 /opt/tools/volatility3/vol.py -q --no-fail -f $1 -r json windows.handles.Handles > /tmp/results/handle.json 2> /tmp/results/handle2.err
fi
}&
{
timeout -v $timestop python3 /opt/tools/volatility3/vol.py -q -f $1 -r json windows.privileges.Privs > /tmp/results/priv.json 2> /tmp/results/priv.err
if [ $? -eq 1 ]
then
  timeout -v $timestop python3 /opt/tools/volatility3/vol.py -q --no-fail -f $1 -r json windows.privileges.Privs > /tmp/results/priv.json 2> /tmp/results/priv2.err
fi
}&
{
timeout -v $timestop python3 /opt/tools/volatility3/vol.py -q -f $1 -r json windows.driverscan > /tmp/results/driverscan.json 2> /tmp/results/driverscan.err
if [ $? -eq 1 ]
then
  timeout -v $timestop python3 /opt/tools/volatility3/vol.py -q --no-fail -f $1 -r json windows.driverscan > /tmp/results/driverscan.json 2> /tmp/results/driverscan2.err
fi
}&
{
timeout -v $timestop python3 /opt/tools/volatility3/vol.py -q -f $1 -r json windows.driverirp > /tmp/results/driverirp.json 2> /tmp/results/driverirp.err
if [ $? -eq 1 ]
then
  timeout -v $timestop python3 /opt/tools/volatility3/vol.py -q --no-fail -f $1 -r json windows.driverirp > /tmp/results/driverirp.json 2> /tmp/results/driverirp2.err
fi
}&
{
timeout -v $timestop python3 /opt/tools/volatility3/vol.py -q -f $1 -r json windows.callbacks.Callbacks > /tmp/results/callbacks.json 2> /tmp/results/callbacks.err
if [ $? -eq 1 ]
then
  timeout -v $timestop python3 /opt/tools/volatility3/vol.py -q --no-fail -f $1 -r json windows.callbacks.Callbacks > /tmp/results/callbacks.json 2> /tmp/results/callbacks2.err
fi
}&
#mem usage:
#python3 /opt/tools/volatility3/vol.py -f $1 -r json windows.virtmap.VirtMap > /tmp/results/virtmap.json &
#yara scan mem
{
timeout -v $timestop python3 /opt/tools/volatility3/vol.py -q -r json -f $1 windows.vadyarascan.VadYaraScan --wide --yara-file /opt/rules/base.yar > /tmp/results/yara.json  2> /tmp/results/yara.err
if [ $? -eq 1 ]
then
  timeout -v $timestop python3 /opt/tools/volatility3/vol.py -q --no-fail -r json -f $1 windows.vadyarascan.VadYaraScan --wide --yara-file /opt/rules/base.yar > /tmp/results/yara.json  2> /tmp/results/yara2.err
fi
}&
{
timeout -v $timestop python3 /opt/tools/volatility3/vol.py -q -r json -f $1 windows.vadyarascan.VadYaraScan --wide --yara-file /opt/rules/malconfscan.yar > /tmp/results/yara-malconf.json 2> /tmp/results/yara-malconf.err
if [ $? -eq 1 ]
then
  timeout -v $timestop python3 /opt/tools/volatility3/vol.py -q --no-fail -r json -f $1 windows.vadyarascan.VadYaraScan --wide --yara-file /opt/rules/malconfscan.yar > /tmp/results/yara-malconf.json 2> /tmp/results/yara-malconf2.err
fi
}&
#yara scan mem no used by proc
{
timeout -v $timestop python3 /opt/tools/volatility3/vol.py -q -r json -f $1 yarascan.YaraScan --wide --yara-file /opt/rules/base.yar > /tmp/results/yaranousedproc.json  2> /tmp/results/yaranousedproc.err
if [ $? -eq 1 ]
then
  timeout -v $timestop python3 /opt/tools/volatility3/vol.py -q --no-fail -r json -f $1 yarascan.YaraScan --wide --yara-file /opt/rules/base.yar > /tmp/results/yaranousedproc.json  2> /tmp/results/yaranousedproc2.err
fi
}&
#process lancé avec la ligne de commande
{
timeout -v $timestop python3 /opt/tools/volatility3/vol.py -q -f $1 -r json windows.cmdline.CmdLine  > /tmp/results/cmdline.json 2> /tmp/results/cmdline.err &
if [ $? -eq 1 ]
then
  timeout -v $timestop python3 /opt/tools/volatility3/vol.py -q --no-fail -f $1 -r json windows.cmdline.CmdLine  > /tmp/results/cmdline.json 2> /tmp/results/cmdline2.err &
fi
}&

timeout -v $timestop python3 /opt/tools/volatility3/vol.py -q -r json -o /tmp/analyze/dump/ -f $1 windows.psscan.PsScan --dump > /tmp/results/psscan.json 2> /tmp/results/psscan.err
if [ $? -eq 1 ]
then
  timeout -v $timestop python3 /opt/tools/volatility3/vol.py -q -r json -o /tmp/analyze/dump/ -f $1 windows.pslist --dump > /tmp/results/psscan.json 2> /tmp/results/psscan2.err
  if [ $? -eq 1 ]
  then
    timeout -v $timestop python3 /opt/tools/volatility3/vol.py -q --no-fail -r json -o /tmp/analyze/dump/ -f $1 windows.pslist --dump > /tmp/results/psscan.json 2> /tmp/results/psscan3.err
  fi
fi
timeout -v $timestop python3 /opt/tools/volatility3/vol.py -q -o /tmp/analyze/dump/ -r json -f $1 windows.modscan.ModScan --dump > /tmp/results/modscan.json 2> /tmp/results/modscan.err
if [ $? -eq 1 ]
then
  timeout -v $timestop python3 /opt/tools/volatility3/vol.py -q --no-fail -o /tmp/analyze/dump/ -r json -f $1 windows.modscan.ModScan --dump > /tmp/results/modscan.json 2> /tmp/results/modscan.err
fi
timeout -v $timestop python3 /opt/tools/volatility3/vol.py -q -o /tmp/analyze/dump/ -r json -f $1 windows.dlllist.DllList --dump > /tmp/results/dlllist.json 2> /tmp/results/dlllist.err
if [ $? -eq 1 ]
then
  timeout -v $timestop python3 /opt/tools/volatility3/vol.py -q --no-fail -o /tmp/analyze/dump/ -r json -f $1 windows.dlllist.DllList --dump > /tmp/results/dlllist.json 2> /tmp/results/dlllist2.err
fi
timeout -v $timestop python3 /opt/tools/volatility3/vol.py -q -f $1 -o /tmp/analyze/dump/ -r json  windows.malfind.Malfind --dump > /tmp/results/malfind.json 2> /tmp/results/malfind.err
if [ $? -eq 1 ]
then
  timeout -v $timestop python3 /opt/tools/volatility3/vol.py -q --no-fail -f $1 -o /tmp/analyze/dump/ -r json  windows.malfind.Malfind --dump > /tmp/results/malfind.json 2> /tmp/results/malfind2.err
fi
#extra
#timeout -v $timestop strings --radix=x $1 |grep "chaine" > /tmp/results/strings_file.txt
#timeout -v $timestop python3 /opt/tools/volatility3/vol.py -q --no-fail -f $1  windows.strings.Strings --strings-file /tmp/results/strings_file.txt > /tmp/results/strings.json 2> /tmp/results/strings.err
#rename file
timeout -v $timestop python3 /opt/tools/changename.py /tmp/results/psscan.json /tmp/analyze/dump/ > /tmp/results/changename.log  2> /tmp/results/changename.err
#scan file
(timeout -v $timestop clamscan -ir --no-summary --max-filesize=800M --max-scansize=800M /tmp/analyze/dump/  | tee -a /tmp/results/clamavresults.log) &
timeout -v $timestop python /opt/tools/Loki/loki.py --dontwait --intense -l /tmp/results/lokiresults.log -s 100000 -p /tmp/analyze/dump/ --csv > /tmp/results/loki.log 2> /tmp/results/loki.err &
#Check proc with vad
mkdir /tmp/analyze/dumpvad/
mkdir /tmp/analyze/dumpcon/
timeout -v $timestop python3 /opt/tools/vadinfo.py /tmp/results/vadinfo.json $1 > /tmp/results/vadinfopy.log  2> /tmp/results/vadinfopy.err
echo "Wait end of process in background $(date)"
wait
find /tmp/results/ -iname '*.err' -size 0 -print -delete > /dev/null 2> /dev/null
for p in $(ls /tmp/results/*.err);do if ! grep -iE 'line [0-9]+, in <|timeout:|faulty layer implementation' $p > /dev/null ;then rm $p ;else echo Error during scan more info: $p;fi ;done
echo "Create Timeline"
python3 /opt/tools/vol2tl.py $1 2> /tmp/results/createtl.err
echo "Finish!"
