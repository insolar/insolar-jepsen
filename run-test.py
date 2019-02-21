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

# to make `sed` work properly, otherwise it failes with an error:
# sed: RE error: illegal byte sequence
os.environ["LC_ALL"] = "C"
os.environ["LANG"] = "C"
os.environ["LC_CTYPE"] = "C"

def info(msg):
    print("INFO: "+msg)

def run(cmd):
    print("    "+cmd)
    code = subprocess.call(cmd, shell=True)
    if code != 0:
        print("Command `%s` returned non-zero status: %d" %
              (cmd, code))
        sys.exit(1)

def get_output(cmd):
    data = subprocess.check_output(cmd, shell=True)
    data = data.decode('utf-8').strip()
    return data

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
    data = get_output("kubectl get pods -l app=insolar-jepsen -o=json | "+\
        """jq -r '.items[] | .metadata.name + " " + .status.podIP'""")
    res = {}
    for kv in data.split("\n"):
        [k, v] = kv.split(' ')
        res[k] = v
    return res

def k8s_stop_pods_if_running():
    info("stopping pods if they are running")
    run("kubectl delete -f jepsen-pods.yml 2>/dev/null || true")
    while True:
        data = get_output("kubectl get pods -l app=insolar-jepsen -o=json | "+\
            "jq -r '.items[].metadata.name' | wc -l")
        info("running pods: "+data)
        if data == "0":
            break
        time.sleep(1)

def k8s_start_pods():
    info("starting pods")
    run("kubectl apply -f jepsen-pods.yml")
    while True:
        data = get_output("kubectl get pods -l app=insolar-jepsen -o=json | "+\
            "jq -r '.items[].status.phase' | grep Running | wc -l")
        info("running pods: "+data)
        if data == str(NPODS):
            break
        time.sleep(1)

parser = argparse.ArgumentParser(description='Execute a simple "pod down/pod up" Jepsen test')
parser.add_argument(
    '-b', '--rebuild', action="store_true",
    help='rebuild the project inside all containers (expensive and error-prone operation!)')
args = parser.parse_args()

k8s_stop_pods_if_running()
k8s_start_pods()
# if pod is started it doesn't mean it's ready to accept connections
time.sleep(3)

if args.rebuild:
    info("building insolar from master on all pods")
    info("hopefully no one will commit and the code on all pods will be the same")
    for pod in range(1, NPODS+1):
        ssh(pod, "cd "+INSPATH+" && "+\
            "git checkout master && git pull && make clean build")

info("building configs based on provided templates")
run("rm -r /tmp/insolar-jepsen-configs || true")
run("cp -r ./config-templates /tmp/insolar-jepsen-configs")
pod_ips = k8s_get_pod_ips()

for k in pod_ips.keys():
    rfrom = k.upper()
    rto = pod_ips[k]
    run("find /tmp/insolar-jepsen-configs -type f -print | grep -v .bak "+\
        "| xargs sed -i.bak 's/"+rfrom+"/"+rto+"/g'")

info("extracting `data` directory from .tar.xz file")
run("rm -r /tmp/insolar-jepsen-data || true")
run("mkdir /tmp/insolar-jepsen-data")
run("tar -xvf ./config-templates/data.tar.xz -C /tmp/insolar-jepsen-data")

info("copying keys, configs, certificates and `data` directory to all pods")
for pod in range(1, (NPODS-1)+1): # exclude the last pod, pulsar
    path = INSPATH+"/scripts/insolard/discoverynodes/"+str(pod)
    ssh(pod, "mkdir -p "+path)
    scp_to(pod, "/tmp/insolar-jepsen-configs/node_0"+str(pod-1)+".json", path)
    scp_to(pod, "/tmp/insolar-jepsen-configs/cert"+str(pod)+".json", path+"/cert.json")
    scp_to(pod, "/tmp/insolar-jepsen-configs/insolar_"+str(pod)+".yaml", path)
    ssh(pod, "rm -r " + path+"/data || true") # prevents creating data/data directory
    scp_to(pod, "/tmp/insolar-jepsen-data/data", path+"/data", flags='-r')
    scp_to(pod, "/tmp/insolar-jepsen-configs/root_member_keys.json", INSPATH)

info("starting pulsar (before anything else, otherwise consensus will not be reached)")
ssh(NPODS, "mkdir -p "+INSPATH+"/scripts/insolard/configs/")
scp_to(NPODS, "/tmp/insolar-jepsen-configs/pulsar.yaml", INSPATH+"/pulsar.yaml")
scp_to(NPODS, "/tmp/insolar-jepsen-configs/bootstrap_keys.json", INSPATH+"/scripts/insolard/configs/bootstrap_keys.json")
ssh(NPODS, "cd " + INSPATH + """ && tmux new-session -d -s pulsard \\"./bin/pulsard -c pulsar.yaml; sh\\" """)

info("starting insolard's and insgorund's")
for pod in range(1, (NPODS-1)+1): # exclude the last pod, pulsar
    ssh(pod, "cd " + INSPATH + " && tmux new-session -d -s insolard " +\
        """\\"INSOLAR_LOG_LEVEL=Info ./bin/insolard --config """ +\
        "./scripts/insolard/discoverynodes/"+str(pod)+\
        "/insolar_"+str(pod)+""".yaml; sh\\" """)
    if pod in VIRTUALS: # also start insgorund
        # TODO: use IPs to prevent DNS caching!
        ssh(pod, "cd " + INSPATH + " && tmux new-session -d -s insgorund "+\
            """\\"./bin/insgorund -l jepsen-"""+str(pod)+":33305 --rpc jepsen-"+\
            str(pod)+""":33306 --log-level=debug; sh\\" """)

# Run benchmark (to jepsen-2):
# while true; do time ___ ; done
# ./bin/benchmark -c 3 -r 10 -u http://10.1.0.240:19102/api -k=./root_member_keys.json
