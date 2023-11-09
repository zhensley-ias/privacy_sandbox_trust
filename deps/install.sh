#!/bin/bash

# reqs: cmake, Go

git clone https://boringssl.googlesource.com/boringssl
pushd boringssl
mkdir build
pushd build
cmake ..
make
popd && popd

git clone https://github.com/gabime/spdlog.git
pushd spdlog && mkdir build && pushd build
cmake .. && make -j
popd && popd
