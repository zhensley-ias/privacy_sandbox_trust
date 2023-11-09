#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

pushd ${SCRIPT_DIR}

# reqs: cmake, Go
pushd ${SCRIPT_DIR}/boringssl
mkdir build
pushd build
cmake ..
make
popd && popd

pushd ${SCRIPT_DIR}/spdlog && mkdir build && pushd build
cmake .. && make -j
popd && popd


popd
