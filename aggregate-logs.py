#!/usr/bin/env python3

import os
import sys
import subprocess

START_PORT = 32001
END_PORT = 32012
OBSERVER_PORT = 32013
DEBUG = True

ZCAT = "zcat"
if os.uname().sysname.lower() == "darwin":
    ZCAT = "gzcat"


def debug(msg):
    if not DEBUG:
        return
    print("    "+msg)


def run(cmd):
    debug(cmd)
    proc = subprocess.run(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if proc.returncode != 0:
        print("Command `%s` returned non-zero status: %d, output: %s" %
              (cmd, proc.returncode, str(proc.stdout)))


def get_output(cmd):
    debug(cmd)
    data = subprocess.check_output(cmd, shell=True)
    data = data.decode('utf-8').strip()
    return data


def k8s_hostname():
    v = get_output(
        "kubectl get nodes -o json | jq -r '.items[] | .metadata.name' | head -n 1")
    if v == "docker-for-desktop":  # Docker Desktop 2.0, k8s 1.10, docker 18.09
        v = "localhost"
    if v == "docker-desktop":  # Docker Desktop 2.1, k8s 1.14, docker 19.03
        v = "localhost"
    return v


if len(sys.argv) < 2:
    print("Usage: {} <copy_to_directory>".format(sys.argv[0]), file=sys.stderr)
    sys.exit(1)

copy_to_dir = sys.argv[1] + "/"
hostname = k8s_hostname()

print("Info: k8s hostname = "+hostname)

run("""rm """+copy_to_dir+"""all_errors.log""")
run("""rm """+copy_to_dir+"""filtered_errors.log""")

for port in range(START_PORT, END_PORT+1):
    node_dir = copy_to_dir + str(port) + "/"
    run("""rm -r """+node_dir)
    run("""mkdir -p """+node_dir+""" || true """)
    if port == START_PORT:
        run("""scp -o 'StrictHostKeyChecking no' -i ./base-image/id_rsa -P """+str(port) +
            """ gopher@"""+hostname+""":go/src/github.com/insolar/insolar/.artifacts/bench-members/* """+node_dir+""" || true""")
        run("""scp -o 'StrictHostKeyChecking no' -i ./base-image/id_rsa -P """+str(port) +
            """ gopher@"""+hostname+""":go/src/github.com/insolar/insolar/background-bench-*.log.gz """+node_dir+""" || true""" )
        run("""scp -o 'StrictHostKeyChecking no' -i ./base-image/id_rsa -P """+str(port) +
            """ gopher@"""+hostname+""":go/src/github.com/insolar/insolar/backupmanager.log """+node_dir+""" || true""")
    run("""scp -o 'StrictHostKeyChecking no' -i ./base-image/id_rsa -P """+str(port) +
        """ gopher@"""+hostname+""":go/src/github.com/insolar/insolar/*.log.gz """+node_dir)

observer_dir = copy_to_dir + "observer/"
run("""rm -r """+observer_dir)
run("""mkdir -p """+observer_dir+""" || true """)

run("""scp -o 'StrictHostKeyChecking no' -i ./base-image/id_rsa -P """+str(OBSERVER_PORT) +
    """ gopher@"""+hostname+""":go/src/github.com/insolar/observer/*.log """+observer_dir)

run(ZCAT + " " + copy_to_dir + """*/*.log.gz | egrep -n '"level":"(error|fatal|panic)"' """ +
    """ | sort -n > """ + copy_to_dir + """all_errors.log""")

run("""cat """ + copy_to_dir + """all_errors.log """ +
    """ | grep -v "TraceID already set" | grep -v "Failed to process packet" | sort > """ +
    copy_to_dir + """filtered_errors.log""")
