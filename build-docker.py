#!/usr/bin/env python3
# vim: set ai et ts=4 sw=4:

import os
import sys
import subprocess
import time

# the complete rebuild takes ~10 minutes
# docker build --no-cache -t insolar-jepsen --build-arg BRANCH=master .

# test the image, it should throw no errors:
# docker run --rm -it insolar-jepsen

def notify(message):
    run("""which osascript && osascript -e 'display notification " """ + message + """ " with title "Jepsen"' || true""")

def run(cmd):
    print("    "+cmd)
    code = subprocess.call(cmd, shell=True)
    if code != 0:
        print("Command `%s` returned non-zero status: %d" %
              (cmd, code))
        sys.exit(1)

if len(sys.argv) < 2:
    print("Usage: {} branch-name".format(sys.argv[0]))
    sys.exit(1)

branch = sys.argv[1]
print("Going to use branch {}".format(branch))
time.sleep(2)

start = int(time.time())

run("docker image prune -f && docker build -t insolar-jepsen --build-arg CACHE=$(date +%s) --build-arg BRANCH="+branch+" .")

stop = int(time.time())
diff = stop - start

print("Build took {} min {} sec".format(int(diff/60), diff % 60))
notify("Docker build completed!")
