#!/usr/bin/env bash
# Stop and remove the integration-test postgres container.
set -euo pipefail
NAME=soulsociety-pg
if [ "$(docker ps -aq -f name="^${NAME}$")" ]; then
  docker rm -f "$NAME" >/dev/null && echo "removed $NAME"
else
  echo "$NAME not running"
fi
