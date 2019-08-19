#!/usr/bin/env python3
# vim: set ai et ts=4 sw=4:

import os
import sys
import subprocess
import argparse
import json
import time

# Roles:
# jepsen-1: heavy
# jepsen-2: virtual
# jepsen-3: light
# jepsen-4: virtual
# jepsen-5: light
# jepsen-6: pulsar

START_PORT = 32000
VIRTUAL_START_PORT = 19100
INSPATH = "go/src/github.com/insolar/insolar"
NPODS = 6
VIRTUALS = [2, 4] # these pods require local insgorund
LOG_LEVEL = "Debug" # Info
NAMESPACE = "default"
SLOW_NETWORK_SPEED = '4mbps'
FAST_NETWORK_SPEED = '1000mbps'
SMALL_MTU = 1400
NORMAL_MTU = 1500
DEBUG = False
POD_NODES = dict() # is filled below
DEPENDENCIES = ['docker', 'kubectl', 'jq']
C = 5
R = 1

K8S_YAML_TEMPLATE = """
kind: Service
apiVersion: v1
metadata:
  name: {pod_name}
spec:
  type: NodePort
  ports:
    - port: 22
      nodePort: {ssh_port}
  selector:
    name: {pod_name}
---
apiVersion: v1
kind: Pod
metadata:
  name: {pod_name}
  labels:
    name: {pod_name}
    app: insolar-jepsen
spec:
  containers:
    - name: {pod_name}
      image: {image_name}
      imagePullPolicy: {pull_policy}
      securityContext:
        capabilities:
          add:
            - NET_ADMIN
      ports:
        - containerPort: 22
  nodeSelector:
    jepsen: "true"
---
"""

# to make `sed` work properly, otherwise it failes with an error:
# sed: RE error: illegal byte sequence
os.environ["LC_ALL"] = "C"
os.environ["LANG"] = "C"
os.environ["LC_CTYPE"] = "C"

def logto(fname):
    return "2>&1 | tee /dev/tty | gzip --stdout > "+fname+"-$(date +%s).log.gz"

def start_test(msg):
    print("##teamcity[testStarted name='"+msg+"']")

def stop_test(msg):
    print("##teamcity[testFinished name='"+msg+"']")

def info(msg):
    print("INFO: "+msg)

def wait(nsec):
    info("waiting "+str(nsec)+" second"+("s" if nsec > 1 else "")+"...")
    time.sleep(nsec)

def notify(message):
    run("""(which osascript 2>/dev/null 1>&2) && osascript -e 'display notification " """ + message + """ " with title "Jepsen"' || true""")

def check(condition):
    if not condition:
        notify("Test failed")
    assert(condition)

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

def ssh_user_host(pod):
    return "gopher@"+POD_NODES['jepsen-'+str(pod)]

def ssh(pod, cmd):
	run("ssh -o 'StrictHostKeyChecking no' -i ./base-image/id_rsa -p"+\
        str(START_PORT + pod)+" "+ssh_user_host(pod)+\
        """ "bash -c 'source ./.bash_profile ; """+\
        cmd + """ '" 2>/dev/null""")

def ssh_output(pod, cmd):
	return get_output("ssh -o 'StrictHostKeyChecking no' -i ./base-image/id_rsa -p"+\
        str(START_PORT + pod)+" "+ssh_user_host(pod)+\
        """ "bash -c 'source ./.bash_profile ; """+\
        cmd + """ '" 2>/dev/null""")

def scp_to(pod, lpath, rpath, flags=''):
    run("scp -o 'StrictHostKeyChecking no' -i ./base-image/id_rsa -P"+\
        str(START_PORT + pod)+" "+flags+" " + lpath + " "+ssh_user_host(pod)+\
        ":"+rpath+" 2>/dev/null")

def scp_from(pod, rpath, lpath, flags=''):
    run("scp -o 'StrictHostKeyChecking no' -i ./base-image/id_rsa -P"+\
        str(START_PORT + pod)+" " + flags + " "+ssh_user_host(pod)+\
        ":"+rpath+" "+lpath+" 2>/dev/null")

def k8s():
    return "kubectl --namespace "+NAMESPACE+" "

def k8s_gen_yaml(fname, image_name, pull_policy):
	with open(fname, "w") as f:
		for i in range(0, 5+1): # 5 nodes + pulsar
			pod_name = "jepsen-"+str(i+1)
			ssh_port = str(32001 + i)
			descr = K8S_YAML_TEMPLATE.format(
				pod_name = pod_name, ssh_port = ssh_port,
				image_name = image_name, pull_policy = pull_policy)
			f.write(descr)

def k8s_get_pod_ips():
    """
    Returns a map PodName -> PodIP
    """
    data = get_output(k8s()+"get pods -l app=insolar-jepsen -o=json | "+\
        """jq -r '.items[] | .metadata.name + " " + .status.podIP'""")
    res = {}
    for kv in data.split("\n"):
        [k, v] = kv.split(' ')
        res[k] = v
    return res

def k8s_get_pod_nodes():
    """
    Returns a map PodName -> NodeName
    """
    data = get_output(k8s() +"get pods -l app=insolar-jepsen -o=json | "+\
        """jq -r '.items[] | .metadata.name + " " + .spec.nodeName'""")
    res = {}
    for kv in data.split("\n"):
        [k, v] = kv.split(' ')
        if v == "docker-for-desktop": # Docker Desktop 2.0, k8s 1.10, docker 18.09
            v = "localhost"
        if v == "docker-desktop": # Docker Desktop 2.1, k8s 1.14, docker 19.03
            v = "localhost"
        res[k] = v
    return res

def k8s_stop_pods_if_running(fname):
    info("stopping pods if they are running")
    run(k8s()+"delete -f "+fname+" 2>/dev/null || true")
    while True:
        data = get_output(k8s()+"get pods -l app=insolar-jepsen -o=json | "+\
            "jq -r '.items[].metadata.name' | wc -l")
        info("running pods: "+data)
        if data == "0":
            break
        wait(1)
    wait(10) # make sure services and everything else are gone as well

def k8s_start_pods(fname):
    info("starting pods")
    run(k8s()+"apply -f "+fname)
    while True:
        data = get_output(k8s()+"get pods -l app=insolar-jepsen -o=json | "+\
            "jq -r '.items[].status.phase' | grep Running | wc -l")
        info("running pods: "+data)
        if data == str(NPODS):
            break
        wait(1)

def set_network_speed(pod, speed):
    ssh(pod, 'sudo tc qdisc del dev eth0 root || true')
    ssh(pod, 'sudo tc qdisc add dev eth0 root handle 1: tbf rate '+speed+' latency 1ms burst 1540')
    ssh(pod, 'sudo tc qdisc del dev eth0 ingress || true')
    ssh(pod, 'sudo tc qdisc add dev eth0 ingress')
    ssh(pod, 'sudo tc filter add dev eth0 root protocol ip u32 match u32 0 0 police rate '+speed+' burst 10k drop flowid :1')
    ssh(pod, 'sudo tc filter add dev eth0 parent ffff: protocol ip u32 match u32 0 0 police rate '+speed+' burst 10k drop flowid :1')

def set_mtu(pod, mtu):
    ssh(pod, 'sudo ifconfig eth0 mtu '+str(mtu))

def create_simple_netsplit(pod, pod_ips):
    """
    Simulates simplest netsplit: one node is cut-off from the rest of the network
    """
    pod_name = 'jepsen-'+str(pod)
    for current_pod in range(1, NPODS+1):
        if current_pod == pod:
            continue
        current_ip = pod_ips['jepsen-'+str(current_pod)]
        ssh(pod, 'sudo iptables -A INPUT -s '+current_ip+' -j DROP && '+
            'sudo iptables -A OUTPUT -d '+current_ip+' -j DROP')

def fix_simple_netsplit(pod, pod_ips):
    """
    Rolls back an effect of create_simple_netsplit()
    """
    pod_name = 'jepsen-'+str(pod)
    for current_pod in range(1, NPODS+1):
        if current_pod == pod:
            continue
        current_ip = pod_ips['jepsen-'+str(current_pod)]
        ssh(pod, 'sudo iptables -D INPUT -s '+current_ip+' -j DROP && '+
            'sudo iptables -D OUTPUT -d '+current_ip+' -j DROP')

def old_node_is_down(status):
    if 'PulseNumber' in status and \
        'Error' in status :
        return status['PulseNumber'] == -1 and \
            status['Error'] != ''
    else:
        return 0

def new_node_is_down(status):
    if 'pulseNumber' in status:
        return status['pulseNumber'] == -1
    else:
        return 0

def node_is_down(status):
    return old_node_is_down(status) or new_node_is_down(status)

def old_node_status_is_ok(status, nodes_online):
    if 'NetworkState' in status and \
        'ActiveListSize' in status and \
        'WorkingListSize' in status and \
        'Error' in status :
        return status['NetworkState'] == 'CompleteNetworkState' and \
            status['ActiveListSize'] == nodes_online and \
            status['WorkingListSize'] == nodes_online and \
            status['Error'] == ''
    else:
        return 0

def new_node_status_is_ok(status, nodes_online):
    if 'networkState' in status and \
        'activeListSize' in status and \
        'workingListSize' in status :
        return status['networkState'] == 'CompleteNetworkState' and \
            status['activeListSize'] == nodes_online and \
            status['workingListSize'] == nodes_online
    else:
        return 0

def node_status_is_ok(status, nodes_online):
    return old_node_status_is_ok(status, nodes_online) or new_node_status_is_ok(status, nodes_online)

def network_status_is_ok(network_status, nodes_online):
    online_list = [ s for s in network_status if not node_is_down(s)]
    # make sure an expected number of nodes is online
    if len(online_list) != nodes_online:
        info("[NetworkStatus] error - {} nodes online, {} expected".format(len(online_list), nodes_online))
        return False

    # make sure all PulseNumber's are equal
    if len(set([ s['PulseNumber'] for s in online_list])) != 1:
        info("[NetworkStatus] PulseNumber's differ: " + str(network_status))
        return False

    # check node statuses
    for node_status in network_status:
        if node_is_down(node_status):
            continue
        if not node_status_is_ok(node_status, nodes_online):
            info("[NetworkStatus] Node status is not OK: "+str(node_status)+\
                "   (nodes online: "+str(nodes_online)+")")
            return False

    info("[NetworkStatus] Everything is OK")
    return True

def insolar_is_alive(pod_ips, virtual_pod, nodes_online, ssh_pod = 1):
    virtual_pod_name = 'jepsen-'+str(virtual_pod)
    port = VIRTUAL_START_PORT + virtual_pod
    out = ssh_output(ssh_pod, 'cd go/src/github.com/insolar/insolar && '+
        'timelimit -s9 -t10 '+ # timeout: 10 seconds
        './bin/pulsewatcher --single --json --config ./pulsewatcher.yaml')
    network_status = json.loads(out)
    if not network_status_is_ok(network_status, nodes_online):
        return False

    out = ssh_output(ssh_pod, 'cd go/src/github.com/insolar/insolar && '+
        'timelimit -s9 -t10 '+ # timeout: 10 seconds
        './bin/benchmark -b -c '+str(C)+' -r '+str(R)+' -u http://'+pod_ips[virtual_pod_name]+':'+str(port)+'/api '+
        '-k=./scripts/insolard/configs/ | grep Success')
    if out == 'Successes: '+str(C*R):
        return True
    else:
        info('insolar_is_alive() is false, out = "'+out+'"')
        return False

def insolar_is_alive_on_pod(pod):
    out = ssh_output(pod, 'pidof insolard || true')
    return (out != '')

def wait_until_insolar_is_alive(pod_ips, nodes_online, virtual_pod=-1, nattempts=10, pause_sec=10, step=""):
    min_nalive = 2
    nalive = 0
    if virtual_pod == -1:
        virtual_pod = VIRTUALS[0]
    for attempt in range(1, nattempts+1):
        wait(pause_sec)
        try:
            alive = insolar_is_alive(pod_ips, virtual_pod, nodes_online)
            if alive:
                nalive += 1
            info("[Step: "+step+"] Alive check passed "+str(nalive)+"/"+str(min_nalive)+" (attempt "+str(attempt)+" of "+str(nattempts)+")" )
        except Exception as e:
            print(e)
            info("[Step: "+step+"] Insolar is not alive yet (attempt "+str(attempt)+" of "+str(nattempts)+")" )
            nalive = 0
        if nalive >= min_nalive:
            break
    return nalive >= min_nalive

def start_insolard(pod, extra_args = ""):
    ssh(pod, "cd " + INSPATH + " && tmux new-session -d "+extra_args+" " +\
        """\\"INSOLAR_LOG_LEVEL="""+LOG_LEVEL+""" ./bin/insolard --config """ +\
        "./scripts/insolard/discoverynodes/"+str(pod)+\
        "/insolar_"+str(pod)+".yaml --heavy-genesis scripts/insolard/configs/heavy_genesis.json "+\
        logto("insolard")+"""; bash\\" """)

def start_insgorund(pod, pod_ips, extra_args = ""):
    ssh(pod, "cd " + INSPATH + " && tmux new-session -d "+extra_args+" "+\
        """\\"./bin/insgorund -l """+pod_ips["jepsen-"+str(pod)]+":33305 --rpc "+\
        pod_ips["jepsen-"+str(pod)]+":33306 --log-level=debug "+logto("insgorund")+"""; bash\\" """)

def start_pulsard(extra_args = ""):
    ssh(NPODS, "cd " + INSPATH + """ && tmux new-session -d """+\
        extra_args+""" \\"./bin/pulsard -c pulsar.yaml """+\
        logto("pulsar") +"""; bash\\" """)

def kill(pod, proc_name):
    ssh(pod, "killall -s 9 "+proc_name+" || true")

def deploy_insolar():
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
    start_pulsard(extra_args="-s pulsard")

    info("starting insolard's and insgorund's")
    for pod in range(1, (NPODS-1)+1): # exclude the last pod, pulsar
        scp_to(pod, "/tmp/insolar-jepsen-configs/pulsewatcher.yaml", INSPATH+"/pulsewatcher.yaml")
        start_insolard(pod, extra_args="-s insolard")
        if pod in VIRTUALS: # also start insgorund
            start_insgorund(pod, pod_ips, extra_args="-s insgorund")

    alive = wait_until_insolar_is_alive(pod_ips, NPODS-1, step="starting")
    check(alive)
    info("==== Insolar started! ====")
    return pod_ips

def test_stop_start_virtual(pod, pod_ips):
    start_test(str(pod) + ".test_stop_start_virtual")
    info("==== start/stop virtual at pod#"+str(pod)+" test started ====")
    alive_pod = [ p for p in VIRTUALS if p != pod ][0]
    alive = wait_until_insolar_is_alive(pod_ips, NPODS-1, step="before-killing-virtual")
    check(alive)
    info("Killing virtual on pod #"+str(pod)+", testing from pod #"+str(alive_pod))
    kill(pod, "insolard")
    kill(pod, "insgorund") # currently we also have to kill insgorund. It will be fixed in contract compiler.
    alive = wait_until_insolar_is_alive(pod_ips, NPODS-2, virtual_pod = alive_pod, step="virtual-down")
    check(alive)
    info("Insolar is still alive. Re-launching insolard on pod #"+str(pod))
    start_insolard(pod)
    start_insgorund(pod, pod_ips)
    alive = wait_until_insolar_is_alive(pod_ips, NPODS-1, virtual_pod = alive_pod, step="virtual-up")
    check(alive)
    info("==== start/stop virtual at pod#"+str(pod)+" passed! ====")
    stop_test(str(pod) + ".test_stop_start_virtual")

def test_network_slow_down_speed_up(pod_ips):
    start_test("test_network_slow_down_speed_up")
    info("==== slow down / speed up network test started ====")
    for pod in range(1, NPODS+1):
        set_network_speed(pod, SLOW_NETWORK_SPEED)
    alive = wait_until_insolar_is_alive(pod_ips, NPODS-1, step="slow-network")
    check(alive)
    for pod in range(1, NPODS+1):
        set_network_speed(pod, FAST_NETWORK_SPEED)
    alive = wait_until_insolar_is_alive(pod_ips, NPODS-1, step="fast-network")
    check(alive)
    info("==== slow down / speed up network test passed! ====")
    stop_test("test_network_slow_down_speed_up")

def test_virtuals_slow_down_speed_up(pod_ips):
    start_test("test_virtuals_slow_down_speed_up")
    info("==== slow down / speed up virtuals test started ====")
    for pod in VIRTUALS:
        set_network_speed(pod, SLOW_NETWORK_SPEED)
    alive = wait_until_insolar_is_alive(pod_ips, NPODS-1, step="slow-virtuals")
    check(alive)
    for pod in VIRTUALS:
        set_network_speed(pod, FAST_NETWORK_SPEED)
    alive = wait_until_insolar_is_alive(pod_ips, NPODS-1, step="fast-virtuals")
    check(alive)
    info("==== slow down / speed up virtuals test passed! ====")
    stop_test("test_virtuals_slow_down_speed_up")

def test_small_mtu(pod_ips):
    start_test("test_small_mtu")
    info("==== small mtu test started ====")
    for pod in range(1, NPODS+1):
        set_mtu(pod, SMALL_MTU)
    alive = wait_until_insolar_is_alive(pod_ips, NPODS-1, step="small-mtu")
    check(alive)
    for pod in range(1, NPODS+1):
        set_mtu(pod, NORMAL_MTU)
    alive = wait_until_insolar_is_alive(pod_ips, NPODS-1, step="noraml-mtu")
    check(alive)
    info("==== small mtu test passed! ====")
    stop_test("test_small_mtu")

def test_stop_start_pulsar(pod_ips):
    start_test("test_stop_start_pulsar")
    info("==== start/stop pulsar test started ====")
    info("Killing pulsard")
    kill(NPODS, "pulsard")
    # alive = wait_until_insolar_is_alive(pod_ips, NPODS-1, step="pulsar-down")
    # check(alive)
    # info("Insolar is still alive. Re-launching pulsard")
    wait(10)
    info("Starting pulsar")
    start_pulsard()
    alive = wait_until_insolar_is_alive(pod_ips, NPODS-1, step="pulsar-up")
    check(alive)
    info("==== start/stop pulsar test passed! ====")
    stop_test("test_stop_start_pulsar")

def test_netsplit_single_virtual(pod, pod_ips):
    start_test("test_netsplit_single_virtual")
    info("==== netsplit of single virtual at pod#"+str(pod)+" test started ====")
    alive_pod = [ p for p in VIRTUALS if p != pod ][0]
    alive = wait_until_insolar_is_alive(pod_ips, NPODS-1, step="before-netsplit-virtual")
    check(alive)
    info("Emulating netsplit that affects single pod #"+str(pod)+", testing from pod #"+str(alive_pod))
    create_simple_netsplit(pod, pod_ips)
    alive = wait_until_insolar_is_alive(pod_ips, NPODS-2, virtual_pod = alive_pod, step="netsplit-virtual")
    check(alive)
    info("Insolar is alive during netsplit")
    # insolard suppose to die in case of netsplit
    for i in range(0,10):
        if not insolar_is_alive_on_pod(pod):
            break
        info('Insolard is not terminated yet at pod#'+str(pod))
        wait(10)
    check(not insolar_is_alive_on_pod(pod))
    info('Fixing netsplit')
    fix_simple_netsplit(pod, pod_ips)
    info('Restarting insolard at pod#'+str(pod))
    start_insolard(pod)
    alive = wait_until_insolar_is_alive(pod_ips, NPODS-1, virtual_pod = alive_pod, step="netsplit-virtual-relaunched")
    check(alive)
    info("==== netsplit of single virtual at pod#"+str(pod)+" test passed! ====")
    stop_test("test_netsplit_single_virtual")

def check_dependencies():
    info("Checking dependencies...")
    for d in DEPENDENCIES:
        run('which ' + d)
    info("All dependencies found.")

parser = argparse.ArgumentParser(description='Test Insolar using Jepsen-like tests')
parser.add_argument(
    '-d', '--debug', action="store_true",
    help='enable debug output')
parser.add_argument(
    '-s', '--skip-all-tests', action="store_true",
    help='skip all tests, check only deploy procedure')
parser.add_argument(
    '-r', '--repeat', metavar='N', type=int, default=1,
    help='number of times to repeat tests')
parser.add_argument(
    '-n', '--namespace', metavar='X', type=str, default="default",
    help='exact k8s namespace to use')
parser.add_argument(
    '-c', '--ci', action="store_true",
    help='use CI-friendly configuration')
parser.add_argument(
    '-i', '--image', metavar='IMG', type=str, required=True,
    help='Docker image to test')

args = parser.parse_args()

NAMESPACE = args.namespace
DEBUG = args.debug
start_test("prepare")
check_dependencies()

k8s_yaml = "jepsen-pods.yaml"
info("Generating "+k8s_yaml)
k8s_gen_yaml(k8s_yaml, args.image, "IfNotPresent" if args.ci else "Never")
k8s_stop_pods_if_running(k8s_yaml)
k8s_start_pods(k8s_yaml)
POD_NODES = k8s_get_pod_nodes()
wait(10) # if pod is started it doesn't mean it's ready to accept connections

pod_ips = deploy_insolar()
stop_test("prepare")

if args.skip_all_tests:
    notify("Deploy checked, skipping all tests")
    sys.exit(0)

for test_num in range(0, args.repeat):
    # TODO: implement a flag that runs tests in random order
    test_network_slow_down_speed_up(pod_ips)
    test_virtuals_slow_down_speed_up(pod_ips)
    # test_small_mtu(pod_ips) # TODO: this test hangs @ DigitalOcean, fix it
    test_stop_start_pulsar(pod_ips)
    # test_netsplit_single_virtual(VIRTUALS[0], pod_ips) # TODO: make this test pass, see INS-2125
    test_stop_start_virtual(VIRTUALS[0], pod_ips)
    test_stop_start_virtual(VIRTUALS[1], pod_ips) # TODO: starting from 25.03.19 this test doesn't always pass, INS-2181
    info("ALL TESTS PASSED: "+str(test_num+1)+" of "+str(args.repeat))

notify("Test completed!")
