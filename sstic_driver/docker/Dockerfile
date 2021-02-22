FROM ubuntu:latest

RUN apt-get -y update

COPY bzImage Dockerfile rootfs.img run_service.sh  /root/
COPY wrapper.py /root/
RUN export DEBIAN_FRONTEND=noninteractive

RUN apt-get -yq install socat python libglib2.0-dev libfdt-dev libpixman-1-dev zlib1g-dev


