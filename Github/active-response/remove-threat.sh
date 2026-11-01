#!/bin/bash
LOCAL=`dirname $0`
cd $LOCAL
cd ../
PWD=`pwd`
read -r INPUT_JSON
LOG_FILE="${PWD}/../logs/active-responses.log"
echo "DEBUG RAW_JSON=[$INPUT_JSON]" >> ${LOG_FILE}
FILENAME=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.data.virustotal.source.file')
COMMAND=$(echo "$INPUT_JSON" | jq -r '.command')
echo "DEBUG FILENAME=[$FILENAME]" >> ${LOG_FILE}
#------------------------ Analyze command -----------------------#
if [ ${COMMAND} = "add" ]
then
    printf '{"version":1,"origin":{"name":"remove-threat","module":"active-response"},"command":"check_keys","parameters":{"keys":[]}}\n'
    read -r RESPONSE
    COMMAND2=$(echo "$RESPONSE" | jq -r '.command')
    if [ ${COMMAND2} != "continue" ]
    then
        echo "`date '+%Y/%m/%d %H:%M:%S'` $0: $INPUT_JSON Remove threat active response aborted" >> ${LOG_FILE}
        exit 0;
    fi
fi
# Removing file
sudo rm -f "$FILENAME" 2>/dev/null
if [ ! -f "$FILENAME" ]; then
    echo "`date '+%Y/%m/%d %H:%M:%S'` $0: $INPUT_JSON Successfully removed threat" >> ${LOG_FILE}
else
    echo "`date '+%Y/%m/%d %H:%M:%S'` $0: $INPUT_JSON Error removing threat - permission denied or file not found" >> ${LOG_FILE}
fi
exit 0;
