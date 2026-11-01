#!/bin/bash
LOCAL=$(dirname $0); cd $LOCAL; cd ../; PWD=$(pwd)
LOG_FILE="${PWD}/../logs/active-responses.log"
read INPUT_JSON
COMMAND=$(echo $INPUT_JSON | jq -r '.command')
FILE_PATH=$(echo $INPUT_JSON | jq -r '.parameters.alert.syscheck.path')

if [ "${COMMAND}" = "add" ]; then
  if [ -f "${FILE_PATH}" ]; then
    rm -f "${FILE_PATH}"
   echo "webshell-cleanup: $(date '+%Y-%m-%d %H:%M:%S') Web shell supprimé -> ${FILE_PATH}" >> ${LOG_FILE}
  fi
fi
exit 0
