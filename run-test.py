#!/usr/bin/env python3
# vim: set ai et ts=4 sw=4:

import os
import sys
import subprocess
import argparse
import time

START_PORT = 32000
INSPATH = "go/src/github.com/insolar/insolar"
NPODS = 6
VIRTUALS = [2, 4] # these pods require local insgorund

# Roles:
# jepsen-1: heavy
# jepsen-2: virtual
# jepsen-3: light
# jepsen-4: virtual
# jepsen-5: light
# jepsen-6: pulsar

# to make `sed` work properly
# otherwise it failes with an error:
# sed: RE error: illegal byte sequence
os.environ["LC_ALL"] = "C"
os.environ["LANG"] = "C"
os.environ["LC_CTYPE"] = "C"

def run(cmd):
    print("    "+cmd)
    code = subprocess.call(cmd, shell=True)
    if code != 0:
        print("Command `%s` returned non-zero status: %d" %
              (cmd, code))
        sys.exit(1)

def ssh(pod, cmd):
	run("ssh -o 'StrictHostKeyChecking no' -i ./ssh-keys/id_rsa -p"+\
        str(START_PORT + pod)+""" gopher@localhost "bash -c 'source ./.bash_profile ; """+\
        cmd + """ '" 2>/dev/null""")

def scp_to(pod, lpath, rpath, flags=''):
    run("scp -o 'StrictHostKeyChecking no' -i ./ssh-keys/id_rsa -P"+\
        str(START_PORT + pod)+" "+flags+" " + lpath + " gopher@localhost:"+rpath+" 2>/dev/null")

def scp_from(pod, rpath, lpath, flags=''):
    run("scp -o 'StrictHostKeyChecking no' -i ./ssh-keys/id_rsa -P"+\
        str(START_PORT + pod)+" " + flags + " gopher@localhost:"+rpath+" "+lpath+" 2>/dev/null")

def k8s_get_pod_ips():
    """
    Returns a map PodName -> PodIP
    """
    data = subprocess.check_output("kubectl get pods -l app=insolar-jepsen -o=json | "+\
        """jq -r '.items[] | .metadata.name + " " + .status.podIP'""", shell=True)
    data = data.decode('utf-8').strip()
    res = {}
    for kv in data.split("\n"):
        [k, v] = kv.split(' ')
        res[k] = v
    return res

parser = argparse.ArgumentParser(description='Execute a simple "pod down/pod up" Jepsen test')
parser.add_argument(
    '-s', '--skip-build', action="store_true",
    help='skip an expensice `build` step and use cached binaries')
args = parser.parse_args()

if not args.skip_build:
    print("INFO: building insolar from master on all pods")
    # TODO: run in parallel
    for pod in range(1, NPODS+1):
        ssh(pod, "cd "+INSPATH+" && "+\
            "git checkout master && git pull && make clean build")

print("INFO: building configs based on provided templates")
run("rm -r /tmp/insolar-jepsen-configs || true")
run("cp -r ./config-templates /tmp/insolar-jepsen-configs")
pod_ips = k8s_get_pod_ips()

for k in pod_ips.keys():
    rfrom = k.upper()
    rto = pod_ips[k]
    run("find /tmp/insolar-jepsen-configs -type f -print | grep -v .bak "+\
        "| xargs sed -i.bak 's/"+rfrom+"/"+rto+"/g'")

print("INFO: generating root member key on 1st pod and copying `data` directory")
run("rm -r /tmp/insolar-jepsen-data || true")
ssh(1, "cd "+INSPATH+" && bin/insolar -c gen_keys > scripts/insolard/configs/root_member_keys.json")
scp_from(1, INSPATH+"/data", "/tmp/insolar-jepsen-data", flags='-r')

print("INFO: copying keys, configs, certificates and `data` directory to all pods")
for pod in range(1, (NPODS-1)+1): # exclude the last pod, pulsar
    path = INSPATH+"/scripts/insolard/discoverynodes/"+str(pod)
    ssh(pod, "mkdir -p "+path)
    scp_to(pod, "/tmp/insolar-jepsen-configs/node_0"+str(pod-1)+".json", path)
    scp_to(pod, "/tmp/insolar-jepsen-configs/insolar_"+str(pod)+".yaml", path)
    scp_to(pod, "/tmp/insolar-jepsen-configs/cert"+str(pod)+".json", path+"/cert.json")
    scp_to(pod, "/tmp/insolar-jepsen-data", path+"/data", flags='-r')

print("INFO: starting insolard's and insgorund's")
for pod in range(1, (NPODS-1)+1): # exclude the last pod, pulsar
    ssh(pod, "cd " + INSPATH + " && tmux new-session -d -s insolard " +\
        """\\"INSOLAR_LOG_LEVEL=Info ./bin/insolard --config """ +\
        "./scripts/insolard/discoverynodes/"+str(pod)+\
        "/insolar_"+str(pod)+""".yaml; sh\\" """)
    if pod in VIRTUALS: # also start insgorund
        ssh(pod, "cd " + INSPATH + " && tmux new-session -d -s insgorund "+\
            """\\"./bin/insgorund -l jepsen-"""+str(pod)+":33305 --rpc jepsen-"+\
            str(pod)+""":33306 --log-level=debug; sh\\" """)

print("INFO: giving insolard some time to start (10 seconds)")
time.sleep(10)

print("INFO: starting pulsar (before anything else, otherwise consensus will not be reached)")
ssh(NPODS, "mkdir -p "+INSPATH+"/scripts/insolard/configs/")
scp_to(NPODS, "/tmp/insolar-jepsen-configs/pulsar.yaml", INSPATH+"/pulsar.yaml")
scp_to(NPODS, "/tmp/insolar-jepsen-configs/bootstrap_keys.json", INSPATH+"/scripts/insolard/configs/bootstrap_keys.json")
ssh(NPODS, "cd " + INSPATH + """ && tmux new-session -d -s pulsard \\"./bin/pulsard -c pulsar.yaml; sh\\" """)


# TODO: def check_insolar_is_ok, execute benchmark (probably from pod 1, which has root_member_keys.json)

# Run benchmark (to jepsen-2):
# while true; do time ___ ; done
# ./bin/benchmark -c 3 -r 10 -u http://10.1.0.148:19102/api -k=scripts/insolard/configs/root_member_keys.json
