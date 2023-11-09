#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

pushd ${SCRIPT_DIR}

yes Y | rm -r spdlog && yes Y | rm -r boringssl

# reqs: cmake, Go
git config --global http.postBuffer 1048576000
git config --global https.postBuffer 1048576000
git clone -c http.sslverify=false https://boringssl.googlesource.com/boringssl --depth 1
pushd boringssl
mkdir build
pushd build
cmake ..
make
popd && popd

git clone https://github.com/gabime/spdlog.git --depth 1
pushd spdlog && mkdir build && pushd build
cmake .. && make -j
popd && popd


popd
