FROM ubuntu:latest

RUN apt-get -y update

COPY bzImage rootfs.img run_service.sh  /root/
ADD qemu /root/qemu

RUN DEBIAN_FRONTEND=noninteractive apt-get -yq install git socat python libglib2.0-dev libfdt-dev libpixman-1-dev zlib1g-dev ninja-build gcc build-essential
RUN cd /root/qemu && ./configure --target-list=x86_64-softmmu && make -j 5
RUN chmod +x /root/run_service.sh

EXPOSE 1337

#keep that at the end so we use cached image of compiled qemu when we modify it
COPY wrapper.py /root/

WORKDIR /root
CMD /root/run_service.sh

