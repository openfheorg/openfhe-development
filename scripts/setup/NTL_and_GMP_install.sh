#!/bin/bash
# 
# required tools curl, tar, lzip
# 
# sudo apt-get install -y curl tar lzip

## GMP AND NTL INSTALL
### GMP
curl -O https://ftp.gnu.org/gnu/gmp/gmp-6.1.2.tar.lz
tar --lzip -xvf gmp-6.1.2.tar.lz
( \
  pushd ./gmp-6.1.2 || exit -1; \
  ./configure &&  \
  make -j `nproc` && \
  make check &&  \
  sudo make install || exit -1 \
  popd; \
)

rm gmp-6.1.2.tar.lz
rm -rf gmp-6.1.2

### NTL
curl -O https://libntl.org/ntl-10.5.0.tar.gz
tar -xvf ntl-10.5.0.tar.gz
( \
  pushd ./ntl-10.5.0/src || exit -1; \
  ./configure NTL_THREADS=on NTL_THREAD_BOOST=on NTL_EXCEPTIONS=on SHARED=on NTL_STD_CXX11=on NTL_SAFE_VECTORS=off TUNE=generic && \
  make -j `nproc` && \
  make check && \
  sudo make install || exit -1; \
  popd; \
)

rm ntl-10.5.0.tar.gz
rm -rf ntl-10.5.0
