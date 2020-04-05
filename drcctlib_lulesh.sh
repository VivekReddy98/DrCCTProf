#! /bin/bash

# set -euo pipefail

CUR_DIR=$(pwd)
BUILD_PATH=${CUR_DIR}/build

echo "Prepare build directory and log directory.."
# init logs directory and the name of next make log file
TIMESTAMP=$(date +%s)
BUILD_LOG_PATH=${CUR_DIR}/logs
if [ ! -d ${BUILD_LOG_PATH} ]; then
    mkdir ${BUILD_LOG_PATH}
fi
MAKE_LOG_FILE=${BUILD_LOG_PATH}/remake.log
echo -e "Enter \033[34m${BUILD_PATH}\033[0m.."

cd ${BUILD_PATH}
echo -e "Running make..(See \033[34m${MAKE_LOG_FILE}\033[0m for detail)"
make -j >${MAKE_LOG_FILE} 2>&1 && echo -e "\033[32m Rebuild successfully! \033[0m" || (echo -e "\033[31m Rebuild fail! \033[0m"; exit -1)

echo -e "Leave \033[34m${BUILD_PATH}\033[0m.."
# leave BUILD_PATH
cd ${CUR_DIR}
RUN_DIRECTORY_64=${BUILD_PATH}/bin64
RUN_DIRECTORY_32=${BUILD_PATH}/bin32
RUN_DIRECTORY=${RUN_DIRECTORY_32}
if [ ! -d ${RUN_DIRECTORY_64} ]; then
    RUN_DIRECTORY=${RUN_DIRECTORY_32}
else
    RUN_DIRECTORY=${RUN_DIRECTORY_64}
fi

echo -e "Build Lulesh1.0.."
LULESH_SOURCE_PATH=${CUR_DIR}/appsamples/src/lulesh1.0
LULESH_BUILD_PATH=${CUR_DIR}/appsamples/build
LULESH=${LULESH_BUILD_PATH}/lulesh-par-original
# g++ -g -O3 -fopenmp -fno-inline ${LULESH_SOURCE_PATH}/luleshOMP-0611.cc ${LULESH_SOURCE_PATH}/instrument.cc -DPOLYBENCH_TIME -o ${LULESH}
g++ -g -fopenmp -fno-inline ${LULESH_SOURCE_PATH}/luleshOMP-0611.cc ${LULESH_SOURCE_PATH}/instrument.cc -DPOLYBENCH_TIME -o ${LULESH}
echo -e "Success build Lulesh1.0.."

cd ${BUILD_LOG_PATH}

BACKGROUNDRUN=$2

for i in 1
do
NPROC=${i}
export OMP_NUM_THREADS=${NPROC}
echo $OMP_NUM_THREADS
export OMP_DYNAMIC=FALSE
export KMP_SCHEDULE=static,balanced
export GOMP_CPU_AFFINITY="0"
echo "run lulesh1.0"
(time ${LULESH} $1 ) > runtime.lulesh.$1.log 2>&1
# echo "run drcctlib_cct_only lulesh1.0"
# (time ${RUN_DIRECTORY}/drrun -t drcctlib_cct_only -- ${LULESH} > client.drcctlib_cct_only.lulesh.log.${TIMESTAMP} 2>&1) > runtime.drcctlib_cct_only.lulesh.${TIMESTAMP} 2>&1
# echo "run drcctlib_memory_only lulesh1.0"
# (time ${RUN_DIRECTORY}/drrun -t drcctlib_memory_only -- ${LULESH} > client.drcctlib_memory_only.lulesh.log.${TIMESTAMP} 2>&1) > runtime.drcctlib_memory_only.lulesh.${TIMESTAMP} 2>&1
# echo "run drcctlib_all_instr_cct lulesh1.0"
# (time ${RUN_DIRECTORY}/drrun -t drcctlib_all_instr_cct -- ${LULESH} > client.drcctlib_all_instr_cct.lulesh.log.${TIMESTAMP} 2>&1) > runtime.drcctlib_all_instr_cct.lulesh.${TIMESTAMP} 2>&1
# echo "run drcctlib_instr_statistics lulesh1.0"
# (time ${RUN_DIRECTORY}/drrun -t drcctlib_instr_statistics -- ${LULESH} > client.drcctlib_instr_statistics.lulesh.log.${TIMESTAMP} 2>&1) > runtime.drcctlib_instr_statistics.lulesh.${TIMESTAMP} 2>&1
# echo "run drcctlib_reuse_distance lulesh1.0"
# (time ${RUN_DIRECTORY}/drrun -t drcctlib_reuse_distance -- ${LULESH} > client.drcctlib_reuse_distance.lulesh.log.${TIMESTAMP} 2>&1) > runtime.drcctlib_reuse_distance.lulesh.${TIMESTAMP} 2>&1
# echo "run drcctlib_reuse_distance lulesh1.0"
# if [ -n "$2" ] && [ "$2" == "1" ]
# then
#     (nohup time ${RUN_DIRECTORY}/drrun -t drcctlib_reuse_distance -- ${LULESH} $1 > client.drcctlib_reuse_distance.lulesh.$1.log.${TIMESTAMP} 2>&1) > runtime.drcctlib_reuse_distance.lulesh.$1.log.${TIMESTAMP} 2>&1 &
# else
#     (time ${RUN_DIRECTORY}/drrun -t drcctlib_reuse_distance -- ${LULESH} $1 > client.drcctlib_reuse_distance.lulesh.$1.log.${TIMESTAMP} 2>&1) > runtime.drcctlib_reuse_distance.lulesh.$1.log.${TIMESTAMP} 2>&1
# fi

cd ${BUILD_LOG_PATH}
echo "run drcctlib_reuse_distance_hpc_fmt ${LULESH}"
(time ${RUN_DIRECTORY}/drrun -t drcctlib_reuse_distance_hpc_fmt -- ${LULESH} $1> client.drcctlib_reuse_distance_hpc_fmt.lulesh.$1.log.${TIMESTAMP} 2>&1) > runtime.drcctlib_reuse_distance_hpc_fmt.lulesh.$1.log.${TIMESTAMP} 2>&1
cd ${CUR_DIR}
${CUR_DIR}/machine_custom_hpc_fmt.sh lulesh-par-original $LULESH $LULESH_SOURCE_PATH

done