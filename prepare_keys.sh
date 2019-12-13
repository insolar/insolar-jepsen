#!/bin/bash

rm -r /tmp/jepsen-keys || true
mkdir /tmp/jepsen-keys
scp -o 'StrictHostKeyChecking no' -i ./base-image/id_rsa -P32001 -r 'gopher@localhost:go/src/github.com/insolar/insolar/scripts/insolard/configs/migration_*_member_keys.json' /tmp/jepsen-keys/
scp -o 'StrictHostKeyChecking no' -i ./base-image/id_rsa -P32001 -r gopher@localhost:go/src/github.com/insolar/insolar/scripts/insolard/bootstrap.yaml /tmp/jepsen-keys/bootstrap_default.yaml
