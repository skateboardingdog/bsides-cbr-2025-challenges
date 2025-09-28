#!/bin/sh
POSTGRES_USER=postgres POSTGRES_PASSWORD=postgres POSTGRES_DB=shopdb \
  /usr/local/bin/docker-entrypoint.sh postgres &

sleep 2
until pg_isready -U postgres; do
  echo "Waiting for PostgreSQL..."
  sleep 1
done

su -s /bin/sh appuser -c /app/server