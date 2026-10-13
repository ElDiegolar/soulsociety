#!/usr/bin/env bash
# Start a throwaway postgres:16 for integration tests (host port 54329).
set -euo pipefail
NAME=soulsociety-pg
PORT=54329
if [ "$(docker ps -aq -f name="^${NAME}$")" ]; then
  if [ -z "$(docker ps -q -f name="^${NAME}$")" ]; then docker start "$NAME" >/dev/null; fi
else
  docker run -d --name "$NAME" \
    -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=postgres \
    -p "${PORT}:5432" postgres:16 >/dev/null
fi
echo "waiting for postgres on :${PORT} ..."
for i in $(seq 1 60); do
  if docker exec "$NAME" pg_isready -U postgres -h 127.0.0.1 -q 2>/dev/null \
     && docker exec "$NAME" psql -U postgres -d postgres -qAtc 'select 1' >/dev/null 2>&1; then
    echo "postgres ready: postgres://postgres:postgres@127.0.0.1:${PORT}/postgres"
    exit 0
  fi
  sleep 1
done
echo "postgres did not become ready" >&2
docker logs --tail 20 "$NAME" >&2 || true
exit 1
