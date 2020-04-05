#! /bin/bash

CUR_DIR=$(pwd)

BUILD_LOG_PATH=${CUR_DIR}/logs
echo -e "Remove \033[34m${BUILD_LOG_PATH}\033[0m.."
rm -rf ${BUILD_LOG_PATH}

BUILD_PATH=${CUR_DIR}/build
echo -e "Remove \033[34m${BUILD_PATH}\033[0m.."
rm -rf ${BUILD_PATH}

APPSAMPLES_BUILD=${CUR_DIR}/appsamples/build
echo -e "Remove \033[34m${APPSAMPLES_BUILD}\033[0m.."
rm -rf ${APPSAMPLES_BUILD}

DR_EXT_SRC_PATH=${CUR_DIR}/dynamorio/ext/drcctlib
echo -e "Remove \033[34m${DR_EXT_SRC_PATH}\033[0m.."
rm -rf ${DR_EXT_SRC_PATH}

DR_CLIENT_SRC_PATH=${CUR_DIR}/dynamorio/clients/drcctlib
echo -e "Remove \033[34m${DR_CLIENT_SRC_PATH}*\033[0m.."
rm -rf ${DR_CLIENT_SRC_PATH}*