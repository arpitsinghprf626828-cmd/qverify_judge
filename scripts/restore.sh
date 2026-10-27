#!/bin/sh
# Usage: scripts/restore.sh backups/qverify-XXXX.tar.gz   (stop the stack first: docker compose down)
set -e; [ -f "$1" ] || { echo "usage: $0 backup.tar.gz"; exit 1; }
docker run --rm -v "$(docker volume ls -q | grep qv_data | head -1)":/data -v "$PWD/$(dirname "$1")":/in alpine sh -c "rm -rf /data/* && tar xzf /in/$(basename "$1") -C /data"
echo "Restored. Start with: docker compose up -d"
