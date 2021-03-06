#! /bin/bash

# **********************************************************
# Copyright (c) 2020 Xuhpclab. All rights reserved.
# Licensed under the MIT License.
# See LICENSE file for more information.
# **********************************************************

set -euo pipefail

CUR_DIR=$(cd "$(dirname "$0")";pwd)
SRC=${CUR_DIR}/src
BUILD=${CUR_DIR}/build
if [ ! -d ${BUILD} ]; then
    mkdir ${BUILD}
fi

echo -e "\033[32m Start build test apps... \033[0m"
g++ -g ${SRC}/test_app_cct.cpp -o ${BUILD}/test_app_cct
g++ -g ${SRC}/test_app_multithread.cpp -o ${BUILD}/test_app_multithread -pthread
g++ -g ${SRC}/test_app_reuse.cpp -o ${BUILD}/test_app_reuse
g++ -g ${SRC}/test_app_signal.cpp -o ${BUILD}/test_app_signal
g++ -g ${SRC}/test_app_p0_512.cpp -o ${BUILD}/test_app_p0_512
g++ -g ${SRC}/test_heap_overflow.cpp -o ${BUILD}/test_heap_overflow
gcc -g -O0 ${SRC}/test2.c -o ${BUILD}/test2
gcc -g -O0 ${SRC}/test1.c -o ${BUILD}/test1
echo -e "\033[32m Build test apps successfully! \033[0m"
