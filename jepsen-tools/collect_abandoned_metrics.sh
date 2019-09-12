#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
FILE=$DIR/pod_ips
IPS=$(cat "$FILE")
PORT=8080
METRIC_NAME="insolar_requests_abandoned{"
#METRIC_NAME="insolar_process_open_fds{"

for ip in $IPS
do
metric=$(curl -s "$ip":$PORT/metrics | grep $METRIC_NAME)
echo "$ip":"$metric"
done