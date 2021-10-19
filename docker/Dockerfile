FROM ubuntu:20.04

ARG repository="palisade-development"
ARG branch=master
ARG tag=master
ARG CC_param=/usr/bin/gcc-10
ARG CXX_param=/usr/bin/g++-10
ARG no_threads=1

ENV DEBIAN_FRONTEND=noninteractive
ENV CC $CC_param
ENV CXX $CXX_param

#install pre-requisites for PALISADE
RUN apt update && apt install -y git \ 
                                 build-essential \
                                 gcc-10 \
                                 g++-10 \
                                 cmake \ 
                                 autoconf \
                                 clang-10 \
                                 libomp5 \
                                 libomp-dev \
                                 doxygen \
                                 graphviz \
                                 libboost-all-dev=1.71.0.0ubuntu2
                                  
RUN apt-get clean && rm -rf /var/lib/apt/lists/*

#git clone the palisade-development repository and its submodules (this always clones the most latest commit)
RUN git clone https://gitlab.com/palisade/$repository.git && cd $repository && git checkout $branch && git checkout $tag && git submodule sync --recursive && git submodule update --init  --recursive

#installing PALISADE and running tests
RUN mkdir /$repository/build && cd /$repository/build && cmake .. && make -j $no_threads && make install && make testall

