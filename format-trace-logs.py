#!/usr/bin/env python3
# vim: set ai et ts=4 sw=4:

import json
import sys

for line in sys.stdin:
    line = line.strip()
    [fname, log] = line.split(":", maxsplit=1)
    print(json.loads(log)["time"]+" "+fname+" "+log)
