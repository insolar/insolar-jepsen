#!/usr/bin/env python3

import sys
import subprocess

START_PORT = 32001
END_PORT = 32012
DEBUG = True


def debug(msg):
    if not DEBUG:
        return
    print("    "+msg)


def run(cmd):
    debug(cmd)
    code = subprocess.call(cmd, shell=True)
    if code != 0:
        print("Command `%s` returned non-zero status: %d" %
              (cmd, code))
        sys.exit(1)

def get_output(cmd):
    debug(cmd)
    data = subprocess.check_output(cmd, shell=True)
    data = data.decode('utf-8').strip()
    return data

def k8s_hostname():
    v = get_output("kubectl get nodes -o json | jq -r '.items[] | .metadata.name' | head -n 1")
    if v == "docker-for-desktop": # Docker Desktop 2.0, k8s 1.10, docker 18.09
        v = "localhost"
    if v == "docker-desktop": # Docker Desktop 2.1, k8s 1.14, docker 19.03
        v = "localhost"
    return v

if len(sys.argv) < 2:
    print("Usage: {} <copy_to_directory>".format(sys.argv[0]), file=sys.stderr)
    sys.exit(1)

copy_to_dir = sys.argv[1] + "/"
hostname = k8s_hostname()

print("Info: k8s hostname = "+hostname)

for port in range(START_PORT, END_PORT+1):
    node_dir = copy_to_dir + str(port) + "/"
    run("""rm -rf """+node_dir)
    run("""mkdir -p """+node_dir+""" || true """)
    if port == START_PORT:
        run("""scp -o 'StrictHostKeyChecking no' -i ./base-image/id_rsa -P """+str(port) +
            """ gopher@"""+hostname+""":go/src/github.com/insolar/insolar/.artifacts/bench-members/members.txt """+node_dir+""" 2>/dev/null || true""")
    run("""scp -o 'StrictHostKeyChecking no' -i ./base-image/id_rsa -P """+str(port) +
        """ gopher@"""+hostname+""":go/src/github.com/insolar/insolar/*.log """+node_dir+""" 2>/dev/null """)

run("""grep -rn " ERR " """ + copy_to_dir +
    """ | sort > """ + copy_to_dir + """all_errors.log""")

run("""grep -rn " ERR " """ + copy_to_dir + """*/*.log""" +
    """ | grep -v "TraceID already set" | grep -v "Failed to process packet" | sort > """ +
    copy_to_dir + """filtered_errors.log""")
