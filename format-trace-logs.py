#!/usr/bin/env python3
# vim: set ai et ts=4 sw=4:

# Usage:
# grep -r 32bc366d-b144-4765-9483-6be37c55fd9d ./320* > trace.txt
# cat trace.txt | ./format-trace.py | grep -v '"caller":"insolar/bus/bus' | grep -v '"caller":"network/' | sort > trace-sorted.txt

import json, sys

for line in sys.stdin:
    line = line.strip()
    [fname,log] = line.split(":",maxsplit=1)
    print(json.loads(log)["time"]+" "+fname+" "+log)
