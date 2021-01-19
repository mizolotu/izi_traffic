FROM ubuntu:18.04

RUN apt update
RUN apt install -y python3 python3-pip nano net-tools iptables
RUN pip3 install scapy numpy netifaces
RUN pip3 install https://github.com/google-coral/pycoral/releases/download/release-frogfish/tflite_runtime-2.5.0-cp36-cp36m-linux_x86_64.whl

ADD server.py /usr/src/app/server.py
ADD client.py /usr/src/app/client.py
ADD utils.py /usr/src/app
ADD generators /usr/src/app/generators

WORKDIR /usr/src/app