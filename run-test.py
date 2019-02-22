#!/usr/bin/env python3
# vim: set ai et ts=4 sw=4:

import os
import sys
import subprocess
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
    print("    "+cmd)
    data = subprocess.check_output(cmd, shell=True)
    data = data.decode('utf-8').strip()
    return data

def ssh(pod, cmd):
	run("ssh -o 'StrictHostKeyChecking no' -i ./ssh-keys/id_rsa -p"+\
        str(START_PORT + pod)+""" gopher@localhost "bash -c 'source ./.bash_profile ; """+\
        cmd + """ '" 2>/dev/null""")

def ssh_output(pod, cmd):
	return get_output("ssh -o 'StrictHostKeyChecking no' -i ./ssh-keys/id_rsa -p"+\
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

def insolar_is_alive(pod_ips):
    # TODO: also check all processes are alive?
    out = ssh_output(1, 'cd go/src/github.com/insolar/insolar && '+
        './bin/benchmark -c 1 -r 5 -u http://'+pod_ips['jepsen-2']+':19102/api '+
        '-k=./scripts/insolard/configs/root_member_keys.json | grep Success')
    if out == 'Successes: 5':
        return True
    else:
        info('insolar_is_alive() is about to return false, out = "'+out+'"')
        return False

k8s_stop_pods_if_running()
k8s_start_pods()
# if pod is started it doesn't mean it's ready to accept connections
time.sleep(3)

info("building configs based on provided templates")
run("rm -r /tmp/insolar-jepsen-configs || true")
run("cp -r ./config-templates /tmp/insolar-jepsen-configs")
pod_ips = k8s_get_pod_ips()

for k in pod_ips.keys():
    run("find /tmp/insolar-jepsen-configs -type f -print | grep -v .bak "+\
        "| xargs sed -i.bak 's/"+k.upper()+"/"+pod_ips[k]+"/g'")

info("copying configs and fixing certificates on all pods")
for pod in range(1, (NPODS-1)+1): # exclude the last pod, pulsar
    discovery_path = INSPATH+"/scripts/insolard/discoverynodes/"
    pod_path = discovery_path+str(pod)
    ssh(pod, "mkdir -p "+pod_path)
    for k in pod_ips.keys():
        ssh(pod, "find "+discovery_path+" -type f -print "+\
            " | grep -v .bak | xargs sed -i.bak 's/"+k.upper()+"/"+pod_ips[k]+"/g'")
    scp_to(pod, "/tmp/insolar-jepsen-configs/insolar_"+str(pod)+".yaml", pod_path)

info("starting pulsar (before anything else, otherwise consensus will not be reached)")
ssh(NPODS, "mkdir -p "+INSPATH+"/scripts/insolard/configs/")
scp_to(NPODS, "/tmp/insolar-jepsen-configs/pulsar.yaml", INSPATH+"/pulsar.yaml")
ssh(NPODS, "cd " + INSPATH + """ && tmux new-session -d -s pulsard \\"./bin/pulsard -c pulsar.yaml; sh\\" """)

info("starting insolard's and insgorund's")
for pod in range(1, (NPODS-1)+1): # exclude the last pod, pulsar
    scp_to(pod, "/tmp/insolar-jepsen-configs/pulsewatcher.yaml", INSPATH+"/pulsewatcher.yaml")
    ssh(pod, "cd " + INSPATH + " && tmux new-session -d -s insolard " +\
        """\\"INSOLAR_LOG_LEVEL=Info ./bin/insolard --config """ +\
        "./scripts/insolard/discoverynodes/"+str(pod)+\
        "/insolar_"+str(pod)+""".yaml; sh\\" """)
    if pod in VIRTUALS: # also start insgorund
        ssh(pod, "cd " + INSPATH + " && tmux new-session -d -s insgorund "+\
            """\\"./bin/insgorund -l """+pod_ips["jepsen-"+str(pod)]+":33305 --rpc "+\
            pod_ips["jepsen-"+str(pod)]+""":33306 --log-level=debug; sh\\" """)

alive = False
nattempts = 10
for attempt in range(1, nattempts+1):
    info("waiting 10 seconds...")
    time.sleep(10)
    try:
        alive = insolar_is_alive(pod_ips)
    except Exception as e:
        print(e)
        info("Insolar is not alive yet (attampt "+str(attempt)+" of "+str(nattempts)+")" )
    if alive:
        break
info("IS ALIVE: "+str(alive))

# killall -s 9 ./bin/insolard
