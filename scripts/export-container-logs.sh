#!/usr/bin/env bash

BASE_DIR="$(dirname "$0")"
. "${BASE_DIR}/common.sh"

OUTPUT_DIR="logs"
mkdir -p ${OUTPUT_DIR}

if [ $APP_ENV == 'qa' ]
then
  USER=$(whoami)
  sudo chown $USER ${OUTPUT_DIR}
fi

CONTAINERS=$(docker ps -a --format '{{.Names}}')
for CONTAINER in ${CONTAINERS}; do
    docker logs ${CONTAINER} >& ${OUTPUT_DIR}/${CONTAINER}.log
done

echo "Successfully exported logs in ${OUTPUT_DIR} directory."
