FROM ubuntu:latest

RUN apt-get -y update && \
    DEBIAN_FRONTEND=noninteractive apt-get -yq install \
        git \
        socat \
        python \
        libglib2.0-dev \
        libfdt-dev \
        libpixman-1-dev \
        zlib1g-dev \
        ninja-build \
        gcc \
        build-essential && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

ADD qemu /root/qemu

RUN cd /root/qemu && ./configure --target-list=x86_64-softmmu && make -j 5

EXPOSE 1337

#keep that at the end so we use cached image of compiled qemu when we modify it
COPY bzImage rootfs.img run_service.sh wrapper.py /root/

RUN chmod +x /root/run_service.sh

WORKDIR /root
CMD /root/run_service.sh

