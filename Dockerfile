#Docker to analyze memory image to create timeline oriented malware search
FROM debian:buster
MAINTAINER Lionel PRAT <lionel.prat9@gmail.com>

# Install packages from apt repository
USER root
RUN apt-get update && apt-get install --no-install-recommends -y \
  automake \
  build-essential \
  git \
  ipython \
  libbz2-dev \
  libc6-dev \
  libfreetype6-dev \
  libgdbm-dev \
  libjansson-dev \
  libmagic-dev \
  libreadline-gplv2-dev \
  libtool \
  python3-dev \
  python3 \
  python3-pip \
  python3-setuptools \
  python-dev \
  python \
  python-setuptools \
  python-pip \
  tar \
  unzip \
  wget \
  nano \
  curl \
  zlib1g \
  zlib1g-dev \
  clamav \
  libssl-dev \
  flex \
  bison \
  libtool \
  pkg-config

#Loki need
RUN pip install wheel
RUN pip install yara-python psutil netaddr pylzma colorama
RUN pip3 install wheel
RUN pip3 install -U pefile capstone distorm3 iocextract pycryptodome jsonschema

#RUN mkdir /tmp/vol3/ && cd /tmp/vol3 && \
#   curl -fL https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip -o linux.zip     && \
#    unzip linux.zip                                                                                    && \
#    curl -fL https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip -o mac.zip         && \
#    unzip mac.zip                                                                                      && \
#    curl -fL https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip -o windows.zip && \
#    unzip windows.zip

#clamfresh
RUN freshclam

RUN cd /tmp && git clone https://github.com/VirusTotal/yara && cd yara && ./build.sh && make install
RUN cd /tmp && \
    git clone --recursive https://github.com/VirusTotal/yara-python && \
    cd yara-python                                                  && \
    python3 setup.py build && \
    python3 setup.py install

#Add rules
RUN mkdir /opt/rules/
ADD rules /opt/rules/
# https://kb.vmware.com/s/article/2003941
RUN mkdir /opt/tools/
RUN wget https://download3.vmware.com/software/vmw-tools/vmss2core/vmss2core-Linux64 -O  /opt/tools/vmss2core && chmod +x /opt/tools/vmss2core
ADD tools/changename.py /opt/tools/
ADD tools/vadinfo.py /opt/tools/
ADD tools/proc-extract.py /opt/tools/
ADD tools/vol.sh /opt/tools/
ADD tools/vol2tl.py /opt/tools/
ADD patch/patchvol3 /tmp/
ADD patch/patchvol3_dll /tmp/
ADD patch/patchvol3_nofail /tmp/
RUN chmod +x /opt/tools/vol.sh
RUN ldconfig
# Clean up
RUN  apt-get autoremove -y --purge && \
  apt-get clean -y && \
  rm -rf /var/lib/apt/lists/*
