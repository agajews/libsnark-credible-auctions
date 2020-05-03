FROM ubuntu:16.04

WORKDIR /root

RUN apt-get update && apt-get install -y build-essential cmake git libgmp3-dev libprocps4-dev python-markdown libboost-all-dev libssl-dev

RUN apt-get install -y pkg-config

COPY CMakeLists.txt CMakeLists.txt
COPY depends depends
COPY src src

RUN mkdir build && cd build && cmake .. && \
    make

CMD ./build/src/test
