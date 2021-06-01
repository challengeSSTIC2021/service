FROM ubuntu:20.04 as builder

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
        checkinstall \
        build-essential && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

ADD qemu /root/qemu

RUN cd /root/qemu && \
    ./configure --target-list=x86_64-softmmu && \
    make -j 8 && \
    checkinstall -D -y

FROM ubuntu:20.04

COPY --from=builder /root/qemu/qemu*.deb /root/

RUN apt-get -y update && \
    DEBIAN_FRONTEND=noninteractive apt-get -yq --no-install-recommends install \
        socat \
        libglib2.0-bin \
        libpixman-1-0 \
        libfdt1 \
        python3 && \
    dpkg -i /root/qemu*.deb && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /root/qemu*.deb

RUN adduser --disabled-password --gecos '' docker

WORKDIR /home/docker

#keep that at the end so we use cached image of compiled qemu when we modify it
COPY asm.py bzImage rootfs.img run_service.sh wrapper.py /home/docker/

RUN chown -R root:root /home/docker && \
    chmod -R ug-w  /home/docker && \
    chmod +x /home/docker/run_service.sh

EXPOSE 1337

USER docker

CMD /home/docker/run_service.sh


