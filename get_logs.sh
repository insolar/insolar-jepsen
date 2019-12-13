#!/bin/bash

scp -o 'StrictHostKeyChecking no' -i ./base-image/id_rsa -P 32001 gopher@localhost:.bash_profile ./
./aggregate-logs.py /tmp/jepsen-agg/
