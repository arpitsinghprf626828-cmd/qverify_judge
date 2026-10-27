#!/bin/sh
# Backs up all state (keys, vault, models, cases, audit log, users) from the running compose volume to ./backups/qverify-DATE.tar.gz
set -e; mkdir -p backups; F="backups/qverify-$(date +%Y%m%d-%H%M%S).tar.gz"
docker run --rm -v "$(docker volume ls -q | grep qv_data | head -1)":/data -v "$PWD/backups":/out alpine tar czf "/out/$(basename "$F")" -C /data .
echo "Wrote $F  (contains private keys: store encrypted, and keep QV_KEY_PASSPHRASE separately)"
