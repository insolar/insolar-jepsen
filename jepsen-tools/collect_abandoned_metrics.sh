#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
FILE=$DIR/pod_ips
IPS=$(cat "$FILE")
PORT=8080
METRIC_NAME="insolar_requests_abandoned{"

for ip in $IPS
do
    metric=$(curl -s "$ip":$PORT/metrics | grep $METRIC_NAME)
    if [ -n "$metric" ]
    then
        echo "$ip":"$metric"
    fi
done