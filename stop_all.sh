#!/bin/bash

for i in {1..11}
do
  port=$((32000 + i))
  ssh -tt -o 'StrictHostKeyChecking no' -i ./base-image/id_rsa -p $port gopher@localhost "bash -c 'source ./.bash_profile ; killall -s 9 insolard || true'"
done

ssh -tt -o 'StrictHostKeyChecking no' -i ./base-image/id_rsa -p 32012 gopher@localhost "bash -c 'source ./.bash_profile ; killall -s 9 pulsard || true'"
