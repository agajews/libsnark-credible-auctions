FROM ubuntu:16.04

WORKDIR /root

RUN apt-get update && apt-get install -y build-essential cmake git libgmp3-dev libprocps4-dev python-markdown libboost-all-dev libssl-dev

RUN apt-get install -y pkg-config

RUN git clone https://github.com/agajews/libsnark-credible-auctions.git && \
    cd libsnark-credible-auctions && \
    git submodule init && git submodule update && \
    cd depends/libsnark && \
    git submodule init && git submodule update && \
    cd ../.. && \
    mkdir build && cd build && cmake .. && \
    make
