#!/usr/bin/env python3
# vim: set ai et ts=4 sw=4:

import os
import sys
import subprocess
import argparse
import json
import time
import random
import traceback
import datetime

# Roles:
# jepsen-1: heavy
# jepsen-2: light
# jepsen-3: light
# jepsen-4: light
# jepsen-5: light
# jepsen-6: light
# jepsen-7: virtual (not-discovery)
# jepsen-8: virtual (not-discovery)
# jepsen-9: virtual (not-discovery)
# jepsen-10: virtual (not-discovery)
# jepsen-11: virtual (not-discovery)
# jepsen-12: pulsar
# jepsen-13: observer, PostgreSQL, Nginx
# jepsen-14: auth-service, PostgreSQL

START_PORT = 32000
VIRTUAL_START_RPC_PORT = 19000
VIRTUAL_START_ADMIN_PORT = 19100
INSPATH = "go/src/github.com/insolar/mainnet"
OLD_MEMBERS_FILE = ".artifacts/bench-members/members-from-start.txt"
MEMBERS_FILE = ".artifacts/bench-members/members.txt"
LIGHT_CHAIN_LIMIT = 5
PULSE_DELTA = 10

HEAVY = 1
LIGHTS = [2, 3, 4, 5, 6]
VIRTUALS = [7, 8, 9, 10, 11]

DISCOVERY_NODES = [HEAVY] + LIGHTS
NOT_DISCOVERY_NODES = VIRTUALS
NODES = DISCOVERY_NODES + NOT_DISCOVERY_NODES

PULSAR = 12
OBSERVER = 13
AUTHSERVICE = 14
ALL_PODS = NODES + [PULSAR, OBSERVER, AUTHSERVICE]

MIN_ROLES_VIRTUAL = 2
LOG_LEVEL = "Debug"  # Info
NAMESPACE = "default"
SLOW_NETWORK_SPEED = '4mbps'
FAST_NETWORK_SPEED = '1000mbps'
SMALL_MTU = 1400
NORMAL_MTU = 1500
DEBUG = False
POD_NODES = dict()  # is filled below
DEPENDENCIES = ['docker', 'kubectl', 'jq']
C = 5
R = 1

CURRENT_TEST_NAME = ""

K8S_YAML_TEMPLATE = """
kind: Service
apiVersion: v1
metadata:
  name: {pod_name}
  labels:
    app: insolar-jepsen
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
---
"""

# A copy of K8S_YAML_TEMPLATE except `resources` section
K8S_OBSERVER_YAML_TEMPLATE = """
kind: Service
apiVersion: v1
metadata:
  name: {pod_name}
  labels:
    app: insolar-jepsen
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
      resources:
        requests:
          ephemeral-storage: "15Gi"
        limits:
          ephemeral-storage: "15Gi"
      securityContext:
        capabilities:
          add:
            - NET_ADMIN
      ports:
        - containerPort: 22
---
"""


PROXY_PORT_YAML_TEMPLATE = """
kind: Service
apiVersion: v1
metadata:
  name: proxy-{pod_name}-{from_port}
  labels:
    app: insolar-jepsen
spec:
  type: NodePort
  ports:
    - port: {from_port}
      nodePort: {to_port}
  selector:
    name: {pod_name}
---
"""

K8S_AUTHSERVICE_YAML_TEMPLATE = """
apiVersion: v1
kind: Pod
metadata:
  labels:
    app: insolar-jepsen
    component: auth-service
  name: auth-service
spec:
  containers:
  - image: registry.insolar.io/auth-service:v1.0.0
    command: 
      - /opt/app/auth-service
    args:
      - --config
      - /auth-service.yaml
    name: auth-service
    volumeMounts:
    - mountPath: /auth-service.yaml
      name: auth-service-config
      subPath: auth-service.yaml
    workingDir: /
  - env:
    - name: POSTGRES_DB
      value: "auth-service"
    - name: POSTGRES_USER
      value: "auth-service"
    - name: POSTGRES_PASSWORD
      value: "local_password"
    image: postgres:12
    name: postgres
    volumeMounts:
    - mountPath: /docker-entrypoint-initdb.d/auth-service.sql.gz
      name: auth-service-db
      subPath: auth-service.sql.gz
  enableServiceLinks: false
  restartPolicy: Always
  volumes:
  - configMap:
      defaultMode: 420
      name: auth-service
    name: auth-service-config
  - configMap:
      name: auth-service-db
    name: auth-service-db
---
apiVersion: v1
kind: Service
metadata:
  name: auth-service
  labels:
    app: insolar-jepsen
    component: auth-service
spec:
  selector:
    app: insolar-jepsen
    component: auth-service
  ports:
    - protocol: TCP
      port: 8080
      targetPort: 8080
---
apiVersion: v1
data:
  auth-service.yaml: |
    host: http://localhost
    listen: :8080
    exptoken: 900
    issuer: insolar-auth
    secret: GLUEiXzHFLikRlpVbFWVmVY9SN8XuQLgjPKffDy2vno43RCIDOJXvD89mTdaG59G
    admin:
      login: auth-service
      password: 9To9mhHs3FqAYCuO8
    db:
      url: postgres://auth-service:local_password@localhost:5432/auth-service?sslmode=disable
      poolsize: 100
    log:
      level: debug
      adapter: zerolog
      formatter: text
      outputtype: stderr
      outputparallellimit:
      outputparams:
      buffersize: 0
      llbuffersize: 0
kind: ConfigMap
metadata:
  labels:
    app: insolar-jepsen
    component: auth-service
  name: auth-service
---
apiVersion: v1
data:
kind: ConfigMap
binaryData:
  auth-service.sql.gz: H4sICDElD18AA2R1bXAuc3FsALVXW2/aSBR+Dr9i1JckKqCZscfjCdoHGugWLTFtgG0rRUJzBatgs7bJZX/9HttQaG5N1C4SgvG5fec7Z86BVqvRaqGPaV7MMzv+NERGFlLJ3CKzWa1B1ijlPfhuDXJZutorXNssj9MEEdrG6KRnVSzrQ4u213MzJxi/JacH5uoOreez0u9LbRvj/gTlhSzsyibFrIhXNt0U6A+EO5VomepvD5/GZmlncTIrMpnkUhcQaJbbvAz4UFkv49K1TXRq4mQOguPp5H143NnFTozMzEyniUuzFWjM8iKDjxw006TUGvbPJ2ViGohZpvN2botKPZ6fHOdWZnoxW8ticdxEx/B2cpnb023shQX8bpPUGBUgsKXfSqdWuV0t03UphcfgtACsP+AGRLMV5CbnleWNzBIAV6tk6Q3krTdZXNyVaJ3r1Iwa6+RmCXxKtbT5Wmpbpn38mHQmtQb3EKNYpAbUFlauO2VTlIWN5MqebaHkHTS5W8Nx0n037HfQGLJbyTO03qhlrDtodJPY7AzJTbFo5Ta7jrWt2uv8st+d9GurrXJ76xGdNBC8YoNiyHxuMxSNJiiaDofNSqAzC61hZrJAZV2hWNBaN3GxqI7o3zSxteJmbV6maOzSvkgRCh0nUECZQYMBsGuZ3QHxJ9C4p7VGLpcFtHxhZX1ONqtZDKqyquY2oVq0lsDwQuaLQ/2yca8tUmm6tDLZJryQyby8STFELxrQRo1GdzjpXz5O3+hzVIpG6M0h628eL98sNtAt/+yqOO5/mvaj89cXcmd4D8zWfZVGd7zLvzqOJ93LCfo8mHxApHowiMDXRT+aoHdft4+iEboYRH93h9P+93P3y/583j3/0EfkeUK2GH4LL5WTHgB8OUE1sOf5+e72nrgdmzK3Q3yreF430++8eXun+8v3sMspY6ff7+KTbXjg61WMQ8xdRr3+++50OHktxzWMUTS8TyOq5eej4fQiKnMrB942CErsbXEtlyfHj1bm+Owss3O9hLt6ui9FD4Y+gs3wzChEve6k+4qqjD4+QH0Sm+bBtGseDLTmwcxq1mOpWc2e5o8Tp7mfMs3tbGnu5skpen85uoBlBxuw0yBHFFPcwrxFGCLszCdnBLcDH3vcf4vxQ6nH20FIMA1L6VV0lNk1gJdFmh1dXd1yxrCymFgirEedY4ELGHFeQMOQEWuPBPU9r9QUjAc+oRjUPYO1JIERhAtOtfaNh7nAAebKiVB6mmjFma809SWYUyw9gSWWGkuqnKacgyUJseKWh8r3BXYWGwYvZ2XAqNCCYSmo4dzDSlGDFVMeDZ3BATOUhz4XgQmZskYT31ee8Q2jyhCrnNQe1iENcOAL4wEtTAR+4KiCRK3hkgkMSXAuNeHW84zxQ0mIZ0LK/EAT4QWYuADMjHBOBFYQbIw0RFufOEc4V8SDkFJ5VjjhKV9y4sJAW22BORqCIdMEmJCUu5JWwwOltBM+syWvXClMgtBnRlIMWKUURFBtFAmoF2IbUl9oF4Sac0o9A/tdmtAxLZUJLfCHQy0MCTWGOB4xOFTYo8xBsZSCpCRhmIEDbUPuS8MNFN7XnqDCGOaU8JWR3MfMOgeelDQBQKTEOCDA+M4PLbCufEE968AdDaBAYUAIc0fFEWHCDykPBG9ctZ+6ZE8Mvl+4Z4dTL753Hcp2xwFwB6QegnrRkoDx8nJEj/6UfGYgNRFpoiLb2NP7q2E3N3YG62/2boftfBSNJ5fdQfT7pmq91Hu9A98/hEYfLwcX3cuv6K/+14rgp1fZwdf/DfU+xGPA7wH4KfbY3M52ye5H8Q73IOr1v7x6JVdWT3iGVO6vh+l4EP2JVJFZi072mg+gbuK9w2pT/BrKaTSANt+CfeD7ZzgrpQOIT/0Hhb89q3WZUhX6PzzYYW+wDgAA
metadata:
  labels:
    app: insolar-jepsen
    component: auth-service
  name: auth-service-db
"""

# to make `sed` work properly, otherwise it failes with an error:
# sed: RE error: illegal byte sequence
os.environ["LC_ALL"] = "C"
os.environ["LANG"] = "C"
os.environ["LC_CTYPE"] = "C"


def logto(fname, index=""):
    # `tee` is used to see recent logs in tmux. please keep it!
    return "2>&1 | tee /dev/tty | gzip --stdout > " + fname + "_`date +%s`.log.gz"


def start_test(msg):
    global CURRENT_TEST_NAME
    CURRENT_TEST_NAME = msg
    print("##teamcity[testStarted name='%s']" % CURRENT_TEST_NAME)


def fail_test(failure_message):
    global CURRENT_TEST_NAME
    notify("Test failed")
    msg = failure_message \
        .replace("|", "||").replace("'", "|'") \
        .replace("\n", "|n").replace("\r", "|r") \
        .replace("[", "|[").replace("]", "|]")
    print("##teamcity[testFailed name='%s' message='%s']" %
          (CURRENT_TEST_NAME, msg))
    trace = "".join(traceback.format_stack()[:-1]) \
        .replace("|", "||").replace("'", "|'") \
        .replace("\n", "|n").replace("\r", "|r") \
        .replace("[", "|[").replace("]", "|]")
    print("##teamcity[testFailed name='%s' message='%s']" %
          (CURRENT_TEST_NAME, trace))
    print_k8s_events()
    stop_test()
    info("Stops nodes after fail")
    for node in NODES:
        kill(node, "insolard")
    kill(PULSAR, "pulsard")
    wait_until_insolar_is_down()
    sys.exit(1)


def print_k8s_events():
    # Disable many screens of k8s-specific output to stdout
    # print(get_output(k8s() + " get pods -o wide -l app=insolar-jepsen "))
    # print(get_output(k8s() + " describe pods    -l app=insolar-jepsen"))
    # print(get_output(k8s() + " get events"))
    pass


def stop_test():
    global CURRENT_TEST_NAME
    print("##teamcity[testFinished name='%s']" % CURRENT_TEST_NAME)


def info(msg):
    print(str(datetime.datetime.now())+" INFO: "+str(msg))


def wait(nsec):
    info("waiting "+str(nsec)+" second"+("s" if nsec > 1 else "")+"...")
    time.sleep(nsec)


def notify(message):
    run("""(which osascript 2>/dev/null 1>&2) && osascript -e 'display notification " """ +
        message + """ " with title "Jepsen"' || true""")


def check(condition, failure_message):
    if not condition:
        fail_test(failure_message)


def check_alive(condition):
    if not condition:
        out = ssh_output(1, 'cd '+INSPATH+' && ' +
                         'timelimit -s9 -t10 ' +  # timeout: 10 seconds
                         './bin/pulsewatcher --single --config ./pulsewatcher.yaml')
        msg = "Insolar must be alive, but its not:\n" + out
        fail_test(msg)


def check_down(condition):
    if not condition:
        fail_test("Insolar must be down, but its not")


def check_benchmark(condition, out):
    if not condition:
        fail_test("Benchmark return error: \n" + out)


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
        info("Stops nodes after fail")
        for node in NODES:
            kill(node, "insolard")
        kill(PULSAR, "pulsard")
        wait_until_insolar_is_down()
        sys.exit(1)


def get_output(cmd):
    debug(cmd)
    proc = subprocess.run(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        print("Command `%s` returned non-zero status: %d, output: %s, error: %s" %
              (cmd, proc.returncode, str(proc.stdout), str(proc.stderr)))
    out = proc.stdout
    data = out.decode('utf-8').strip()
    return data


def ssh_user_host(pod):
    return "gopher@"+POD_NODES['jepsen-'+str(pod)]


def ssh(pod, cmd):
    run("ssh -tt -o 'StrictHostKeyChecking no' -i ./base-image/id_rsa -p" +
        str(START_PORT + pod)+" "+ssh_user_host(pod) +
        """ "bash -c 'source ./.bash_profile ; """ +
        cmd + """ '" """)


def ssh_output(pod, cmd):
    return get_output("ssh -tt -o 'StrictHostKeyChecking no' -i ./base-image/id_rsa -p" +
                      str(START_PORT + pod)+" "+ssh_user_host(pod) +
                      """ "bash -c 'source ./.bash_profile ; """ +
                      cmd + """ '" """)


def scp_to(pod, lpath, rpath, flags='', ignore_errors=False):
    run("scp -o 'StrictHostKeyChecking no' -i ./base-image/id_rsa -P" +
        str(START_PORT + pod)+" "+flags+" " + lpath + " "+ssh_user_host(pod) +
        ":"+rpath + (" || true" if ignore_errors else ""))


def scp_from(pod, rpath, lpath, flags=''):
    run("scp -o 'StrictHostKeyChecking no' -i ./base-image/id_rsa -P" +
        str(START_PORT + pod)+" " + flags + " "+ssh_user_host(pod) +
        ":"+rpath+" "+lpath)


def k8s():
    return "kubectl --namespace "+NAMESPACE+" "


def k8s_gen_yaml(fname, image_name, pull_policy):
    with open(fname, "w") as f:
        to_port = 31008
        for i in ALL_PODS:
            pod_name = "jepsen-" + str(i)
            ssh_port = str(32000 + i)
            descr = K8S_YAML_TEMPLATE.format(
                pod_name=pod_name,
                ssh_port=ssh_port,
                image_name=image_name,
                pull_policy=pull_policy
            )
            # Proxy PostgreSQL and Nginx ports on OBSERVER
            if i == OBSERVER:
                # Rewrite `descr`
                descr = K8S_OBSERVER_YAML_TEMPLATE.format(
                    pod_name=pod_name,
                    ssh_port=ssh_port,
                    image_name=image_name,
                    pull_policy=pull_policy
                )
                for from_port in [5432, 80]:
                    descr += PROXY_PORT_YAML_TEMPLATE.format(
                        pod_name=pod_name,
                        from_port=from_port,
                        to_port=to_port,
                    )
                    to_port += 1
            if i == AUTHSERVICE:
                descr = K8S_AUTHSERVICE_YAML_TEMPLATE.format(
                    pull_policy=pull_policy
                )
            f.write(descr)


def k8s_get_pod_ips():
    """
    Returns a map PodName -> PodIP
    """
    data = get_output(k8s()+"get pods -l app=insolar-jepsen -o=json | " +
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
    data = get_output(k8s() + "get pods -l app=insolar-jepsen -o=json | " +
                      """jq -r '.items[] | .metadata.name + " " + .spec.nodeName'""")
    res = {}
    for kv in data.split("\n"):
        [k, v] = kv.split(' ')
        if v == "docker-for-desktop":  # Docker Desktop 2.0, k8s 1.10, docker 18.09
            v = "localhost"
        if v == "docker-desktop":  # Docker Desktop 2.1, k8s 1.14, docker 19.03
            v = "localhost"
        res[k] = v
    return res


def k8s_stop_pods_if_running():
    info("stopping pods and services with `insolar-jepsen` label")
    run(k8s()+"delete services -l app=insolar-jepsen 2>/dev/null || true")
    run(k8s()+"delete pods -l app=insolar-jepsen 2>/dev/null || true")
    for n in range(60):
        data = get_output(k8s()+"get pods -l app=insolar-jepsen -o=json | " +
                          "jq -r '.items[].metadata.name' | wc -l")
        info("running pods: "+data)
        if data == "0":
            break
        wait(3)
    else:
        fail_test("k8s_stop_pods_if_running no attempts left")
    wait(20)  # make sure services and everything else are gone as well


def k8s_start_pods(fname):
    info("starting pods")
    run(k8s()+"apply -f "+fname)
    for n in range(60):
        data = get_output(k8s()+"get pods -l app=insolar-jepsen -o=json | " +
                          "jq -r '.items[].status.phase' | grep Running | wc -l")
        info("running pods: "+data)
        if data == str(len(ALL_PODS)):
            break
        wait(3)
    else:
        fail_test("k8s_start_pods no attempts left")


def set_network_speed(pod, speed):
    ssh(pod, 'sudo tc qdisc del dev eth0 root || true')
    ssh(pod, 'sudo tc qdisc add dev eth0 root handle 1: tbf rate ' +
        speed+' latency 1ms burst 1540')
    ssh(pod, 'sudo tc qdisc del dev eth0 ingress || true')
    ssh(pod, 'sudo tc qdisc add dev eth0 ingress')
    ssh(pod, 'sudo tc filter add dev eth0 root protocol ip u32 match u32 0 0 police rate ' +
        speed+' burst 10k drop flowid :1')
    ssh(pod, 'sudo tc filter add dev eth0 parent ffff: protocol ip u32 match u32 0 0 police rate ' +
        speed+' burst 10k drop flowid :1')


def set_mtu(pod, mtu):
    ssh(pod, 'sudo ifconfig eth0 mtu '+str(mtu))


def create_simple_netsplit(pod, pod_ips):
    """
    Simulates simplest netsplit: one node is cut-off from the rest of the network
    """
    for current_pod in ALL_PODS:
        if current_pod == pod:
            continue
        current_ip = pod_ips['jepsen-'+str(current_pod)]
        ssh(pod, 'sudo iptables -A INPUT -s '+current_ip+' -j DROP && ' +
            'sudo iptables -A OUTPUT -d '+current_ip+' -j DROP')


def fix_simple_netsplit(pod, pod_ips):
    """
    Rolls back an effect of create_simple_netsplit()
    """
    for current_pod in ALL_PODS:
        if current_pod == pod:
            continue
        current_ip = pod_ips['jepsen-'+str(current_pod)]
        ssh(pod, 'sudo iptables -D INPUT -s '+current_ip+' -j DROP && ' +
            'sudo iptables -D OUTPUT -d '+current_ip+' -j DROP')


def old_node_is_down(status):
    if 'PulseNumber' in status and \
            'Error' in status:
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
            'Error' in status:
        return status['NetworkState'] == 'CompleteNetworkState' and \
            status['ActiveListSize'] == nodes_online and \
            status['WorkingListSize'] == nodes_online and \
            status['Error'] == ''
    else:
        return 0


def new_node_status_is_ok(status, nodes_online):
    if 'networkState' in status and \
        'activeListSize' in status and \
            'workingListSize' in status:
        return status['networkState'] == 'CompleteNetworkState' and \
            status['activeListSize'] == nodes_online and \
            status['workingListSize'] == nodes_online
    else:
        return 0


def node_status_is_ok(status, nodes_online):
    return old_node_status_is_ok(status, nodes_online) or new_node_status_is_ok(status, nodes_online)


def network_status_is_ok(network_status, nodes_online):
    online_list = [network_status[nodeIndex-1]
                   for nodeIndex in nodes_online if not node_is_down(network_status[nodeIndex-1])]
    # make sure an expected number of nodes is online
    if len(online_list) < len(nodes_online):
        info("[NetworkStatus] error - {} nodes online, {} expected".format(len(online_list), nodes_online))
        return False

    # make sure all PulseNumber's are equal
    pn = set(s['PulseNumber'] for s in online_list)
    if len(pn) != 1:
        info("[NetworkStatus] PulseNumber's differ: " +
             str([s['PulseNumber'] for s in online_list]))
        return False
    else:
        info("[NetworkStatus] PulseNumber is " + str(pn))

    # check node statuses
    for nodeIndex in nodes_online:
        node_status = network_status[nodeIndex-1]
        if node_is_down(node_status):
            continue
        if not node_status_is_ok(node_status, len(nodes_online)):
            info("[NetworkStatus] Node status is not OK: "+str(node_status) +
                 "   (nodes online: "+str(nodes_online)+")")
            return False

    info("[NetworkStatus] Everything is OK")
    return True


def wait_until_current_pulse_will_be_finalized():
    pulse = current_pulse()
    finalized_pulse = get_finalized_pulse_from_exporter()
    while pulse != finalized_pulse:
        info("Current pulse: "+str(pulse) +
             ", finalized pulse: "+str(finalized_pulse))
        wait(1)
        finalized_pulse = get_finalized_pulse_from_exporter()


def get_finalized_pulse_from_exporter():
    token = str(json.loads(ssh_output(HEAVY, 'curl -s "replicator:replicator@auth-service:8080/auth/token"'))["access_token"])
    cmd = 'grpcurl -import-path /home/gopher/go/src -import-path ./go/src/github.com/insolar/mainnet/vendor' +\
          ' -proto /home/gopher/go/src/github.com/insolar/mainnet/pulse_exporter.proto' +\
          ' -H \\"authorization: Bearer {}\\"'.format(token) +\
          ' -H \\"client_type:ValidateHeavyVersion\\"' +\
          ' -H \\"heavy_version:2\\"' +\
          """ -plaintext JEPSEN-1:5678 exporter.PulseExporter.TopSyncPulse"""
    out = ssh_output(HEAVY, cmd)
    pulse = json.loads(out)["PulseNumber"]
    info("exporter said: " + str(pulse))
    return pulse


def benchmark(pod_ips, api_pod=VIRTUALS[0], ssh_pod=1, extra_args="", c=C, r=R, timeout=30, background=False):
    virtual_pod_name = 'jepsen-'+str(api_pod)
    port = VIRTUAL_START_RPC_PORT + api_pod
    out = ""
    try:
        out = ssh_output(ssh_pod, 'cd '+INSPATH+' && ' +
                         ("tmux new-session -d \\\"" if background else "") +
                         'timelimit -s9 -t'+str(timeout)+' ' +
                         './bin/benchmark -c ' + str(c) + ' -r ' + str(r) + ' -a http://'+pod_ips[virtual_pod_name] +
                         ':'+str(port) + '/admin-api/rpc ' +
                         ' -p http://'+pod_ips[virtual_pod_name]+':'+str(port + 100)+'/api/rpc ' +
                         '-k=./scripts/insolard/configs/ ' + extra_args +
                         ' ' + (logto('background-bench-'+str(int(time.time()))) + "\\\"" if background else ""))
    except Exception as e:
        print(e)
        out = "ssh_output() throwed an exception (non-zero return code): "+str(e)
    return out


def migrate_member(pod_ips, api_pod=VIRTUALS[0], ssh_pod=1, members_file=MEMBERS_FILE, c=C*2, timeout=90):
    ok, migration_out = run_benchmark(
        pod_ips, api_pod, ssh_pod, c=c, extra_args='-t=migration -s --members-file=' + members_file, timeout=timeout
    )
    check_benchmark(ok, migration_out)
    ok, migration_out = run_benchmark(
        pod_ips, api_pod, ssh_pod, c=c, withoutBalanceCheck=True, extra_args='-t=migration -m --members-file=' + members_file, timeout=timeout,
    )
    check_benchmark(ok, migration_out)
    ok, out = check_balance_at_benchmark(
        pod_ips, extra_args='-m --members-file=' + members_file + ' --check-all-balance', timeout=timeout
    )
    check_benchmark(ok, out)


def run_benchmark(pod_ips, api_pod=VIRTUALS[0], ssh_pod=1, withoutBalanceCheck=False, extra_args="", c=C, r=R, timeout=90, background=False):
    if withoutBalanceCheck:
        extra_args = extra_args + ' -b'
    out = benchmark(pod_ips, api_pod, ssh_pod,
                    extra_args, c, r, timeout, background)

    if background:
        return True, out

    if 'Successes: '+str(c*r) in out:
        if withoutBalanceCheck or 'Total balance successfully matched' in out:
            return True, out
    return False, out


def check_balance_at_benchmark(pod_ips, api_pod=VIRTUALS[0], ssh_pod=1, extra_args="", c=C, r=R, timeout=30, background=False):
    out = benchmark(pod_ips, api_pod, ssh_pod,
                    extra_args, c, r, timeout, background)

    if background:
        return True, out

    if 'Balances for members from file was successfully checked' in out:
        return True, out
    return False, out


def pulsewatcher_output(ssh_pod=1):
    return ssh_output(ssh_pod, 'cd '+INSPATH+' && ' +
                      'timelimit -s9 -t10 ' +  # timeout: 10 seconds
                      './bin/pulsewatcher --single --json --config ./pulsewatcher.yaml')


def current_pulse(node_index=HEAVY, ssh_pod=1):
    network_status = json.loads(pulsewatcher_output(ssh_pod))
    pn = network_status[node_index]['PulseNumber']
    return pn


def insolar_is_alive(pod_ips, virtual_pod, nodes_online, ssh_pod=1, skip_benchmark=False):
    out = pulsewatcher_output(ssh_pod)
    network_status = json.loads(out)
    if not network_status_is_ok(network_status, nodes_online):
        info('insolar_is_alive() is false, out = "'+out+'"')
        return False

    if skip_benchmark:
        return True

    ok, out = run_benchmark(pod_ips, virtual_pod, ssh_pod,
                            extra_args=" -t=createMember")
    if ok:
        return True
    else:
        info("Benchmark run wasn't success: " + out)
        return False


def insolar_is_alive_on_pod(pod):
    out = ssh_output(pod, 'pidof insolard || true')
    return out != ''


def wait_until_insolar_is_alive(pod_ips, nodes_online, virtual_pod=-1, nattempts=20, pause_sec=5, step="", skip_benchmark=False):
    min_nalive = 3
    nalive = 0
    if virtual_pod == -1:
        virtual_pod = VIRTUALS[0]
    for attempt in range(1, nattempts+1):
        wait(pause_sec)
        try:
            alive = insolar_is_alive(
                pod_ips, virtual_pod, nodes_online, skip_benchmark=skip_benchmark)
            if alive:
                nalive += 1
            info("[Step: "+step+"] Alive check passed "+str(nalive)+"/" +
                 str(min_nalive)+" (attempt "+str(attempt)+" of "+str(nattempts)+")")
        except Exception as e:
            print(e)
            info("[Step: "+step+"] Insolar is not alive yet (attempt " +
                 str(attempt)+" of "+str(nattempts)+")")
            nalive = 0
        if nalive >= min_nalive:
            break
    return nalive >= min_nalive


def start_insolar_net(nodes, pod_ips, extra_args_insolard="", step="", skip_benchmark=False, use_postgresql=False):
    alive = False

    for attempt in range(1, 4):
        info("Insolar net not alive, kill all for clear start")
        for node in NODES:
            kill(node, "insolard")
        info("Starting insolar net (attempt %s)" % str(attempt))
        for pod in nodes:
            start_insolard(pod, use_postgresql=use_postgresql, extra_args=extra_args_insolard)
        info("Check insolar net alive")
        alive = wait_until_insolar_is_alive(
            pod_ips, NODES, step=step, skip_benchmark=skip_benchmark)
        if alive:
            break

    check_alive(alive)


def wait_until_insolar_is_down(nattempts=10, pause_sec=5):
    all_down = False
    for pod in NODES:
        for i in range(0, nattempts):
            if not insolar_is_alive_on_pod(pod):
                all_down = True
                break
            info('Insolard is not terminated yet at pod#'+str(pod))
            all_down = False
            wait(pause_sec)
    return all_down


def run_genesis(use_postgresql=False):
    if use_postgresql:
        database = "postgres"
    else:
        database = "badger"
    ssh(HEAVY, "cd " + INSPATH + " && " +
        "INSOLAR_LOG_LEVEL="+LOG_LEVEL+" ./bin/insolard heavy --config " +
        "./scripts/insolard/"+str(HEAVY) +
        "/insolar_"+str(HEAVY)+".yaml --heavy-genesis scripts/insolard/configs/heavy_genesis.json " +
        "--database=" + database + " " +
        "--genesis-only")


def start_insolard(pod, use_postgresql=False, extra_args=""):
    role = "unknown"
    if pod == HEAVY:
        if use_postgresql:
            start_heavy(pod, extra_args, "postgres")
        else:
            start_heavy(pod, extra_args, "badger")
        return
    elif pod in VIRTUALS:
        role = "virtual"
    elif pod in LIGHTS:
        role = "light"
    ssh(pod, "cd " + INSPATH + " && tmux new-session -d "+extra_args+" " +
        """\\"INSOLAR_LOG_LEVEL="""+LOG_LEVEL+""" ./bin/insolard """+role+""" --config """ +
        "./scripts/insolard/"+str(pod) +
        "/insolar_"+str(pod)+".yaml " +
        logto("insolard")+"""; bash\\" """)


def start_heavy(pod, extra_args="", database=""):
    ssh(pod, "cd " + INSPATH + " && tmux new-session -d "+extra_args+" " +
        """\\"INSOLAR_LOG_LEVEL="""+LOG_LEVEL+""" ./bin/insolard heavy --config """ +
        "./scripts/insolard/"+str(pod) +
        "/insolar_"+str(pod)+".yaml --heavy-genesis=scripts/insolard/configs/heavy_genesis.json " +
        "--database=" + database + " " +
        logto("insolard")+"""; bash\\" """)


def start_pulsard(extra_args=""):
    ssh(PULSAR, "cd " + INSPATH + """ && tmux new-session -d """ +
        extra_args+""" \\"./bin/pulsard -c pulsar.yaml """ +
        logto("pulsar") + """; bash\\" """)


def kill(pod, proc_name):
    ssh(pod, "killall -s 9 "+proc_name+" || true")


def restore_heavy_from_backup(heavy_pod):
    info("Restoring heavy from backup at pod#..."+str(heavy_pod))
    kill(heavy_pod, "backupmanager")
    ssh(heavy_pod, "cd "+INSPATH+" && " +
        "backupmanager prepare_backup -d ./heavy_backup/ && " +
        "rm -r data && cp -r heavy_backup data")


def check_ssh_is_up_on_pods():
    try:
        for pod in NODES + [PULSAR, OBSERVER]:
            out = ssh_output(pod, "echo 1")
            if out != "1":
                return False
    except Exception as e:
        print(e)
        return False
    return True


def wait_until_ssh_is_up_on_pods():
    info("Waiting until SSH daemons are up on all nodes")
    is_up = False
    nchecks = 10
    for check in range(1, nchecks+1):
        is_up = check_ssh_is_up_on_pods()
        if is_up:
            break
        info("SSH daemons are not up yet (attempt " +
             str(check)+" of "+str(nchecks)+")")
        wait(1)
    assert(is_up)
    info("SSH daemons are up!")


def prepare_configs():
    info("Building configs based on provided templates")

    info("Replace old config-templates with new")
    run("rm -r /tmp/insolar-jepsen-configs || true")
    run("cp -r ./config-templates /tmp/insolar-jepsen-configs")
    pod_ips = k8s_get_pod_ips()

    # sorting is needed to replace JEPSEN-10 before JEPSEN-1
    for k in sorted(pod_ips.keys(), reverse=True):
        run("find /tmp/insolar-jepsen-configs -type f -print | grep -v .bak " +
            "| xargs sed -i.bak 's/"+k.upper()+"/"+pod_ips[k]+"/g'")


def deploy_pulsar():
    info("starting pulsar (before anything else, otherwise consensus will not be reached)")
    ssh(PULSAR, "mkdir -p "+INSPATH+"/scripts/insolard/configs/")
    scp_to(PULSAR, "/tmp/insolar-jepsen-configs/pulsar.yaml",
           INSPATH+"/pulsar.yaml")
    start_pulsard(extra_args="-s pulsard")

def deploy_postgresql(pod, service_name):
    info("deploying PostgreSQL @ pod "+str(pod))
    # The base64-encoded string is: listen_addresses = '*'
    # I got tired to fight with escaping quotes in bash...
    ssh(pod, """sudo bash -c \\"echo bGlzdGVuX2FkZHJlc3NlcyA9ICcqJwo= | base64 -d >> /etc/postgresql/11/main/postgresql.conf && echo host all all 0.0.0.0/0 md5 >> /etc/postgresql/11/main/pg_hba.conf && service postgresql start\\" """)
    ssh(pod, """echo -e \\"CREATE DATABASE """+service_name+"""; CREATE USER """+service_name+""" WITH PASSWORD \\x27"""+service_name+"""\\x27; GRANT ALL ON DATABASE """+service_name+""" TO """+service_name+""";\\" | sudo -u postgres psql""")


def deploy_observer_deps():
    deploy_postgresql(OBSERVER, 'observer')
    info("starting Nginx @ pod "+str(OBSERVER))
    scp_to(OBSERVER, "/tmp/insolar-jepsen-configs/nginx_default.conf",
           "/tmp/nginx_default.conf")
    ssh(OBSERVER, """sudo bash -c \\"cat /tmp/nginx_default.conf > /etc/nginx/sites-enabled/default && service nginx start\\" """)

def deploy_observer(path, keep_database=False, public=False):
    cfgs_list = ["observer", "observerapi", "stats-collector", "migrate"]
    build_mode = "all"
    if public:
        build_mode = "all-node"
        cfgs_list = ["observer", "observerapi_public", "migrate"]
    info("deploying observer @ pod "+str(OBSERVER) +
         ", using source code from "+path+"/observer")
    # cleanup after previous deploy, if there was one
    ssh(OBSERVER, "tmux kill-session -t observer || true")
    ssh(OBSERVER, "tmux kill-session -t observerapi || true")
    ssh(OBSERVER, "tmux kill-session -t stats-collector || true")
    ssh(OBSERVER, "rm -rf "+INSPATH+"/../observer || true")
    # ignore_errors=True is used because Observer's dependencies have symbolic links pointing to non-existing files
    scp_to(OBSERVER, path + "/observer", INSPATH +
           "/../observer", flags="-r", ignore_errors=True)
    ssh(OBSERVER, "cd %s/../observer && GO111MODULE=on make %s && mkdir -p .artifacts" % (INSPATH, build_mode))


    for cqw in cfgs_list:
        scp_to(OBSERVER, f"/tmp/insolar-jepsen-configs/{cqw}.yaml",
               INSPATH+f"/../observer/.artifacts/{cqw}.yaml")

    if not keep_database:
        info("purging observer's database...")
        ssh(OBSERVER, """echo -e \\"DROP DATABASE observer; CREATE DATABASE observer;\\" | sudo -u postgres psql""")
        ssh(OBSERVER, "cd "+INSPATH +
            "/../observer && GO111MODULE=on make migrate-init")
        ssh(OBSERVER, "cd " + INSPATH +
            "/../observer && GO111MODULE=on make migrate")
    # run observer
    ssh(OBSERVER, """tmux new-session -d -s observer \\"cd """+INSPATH +
        """/../observer && ./bin/observer --config=./.artifacts/observer.yaml 2>&1 | tee -a observer.log; bash\\" """)
    # run observer-api
    if public:
        ssh(OBSERVER, """tmux new-session -d -s observerapi \\"cd """+INSPATH +
            """/../observer && ./bin/api --config=./.artifacts/observerapi_public.yaml 2>&1 | tee -a observerapi.log; bash\\" """)
    else:
        ssh(OBSERVER, """tmux new-session -d -s observerapi \\"cd """ + INSPATH +
            """/../observer && ./bin/api --config=./.artifacts/observerapi.yaml 2>&1 | tee -a observerapi.log; bash\\" """)
    if not public:
        # run stats-collector every 10 seconds
        ssh(OBSERVER, "tmux new-session -d -s stats-collector " +
            """\\"cd """+INSPATH+"""/../observer && while true; do ./bin/stats-collector --config=./.artifacts/stats-collector.yaml 2>&1 | tee -a stats-collector.log;  sleep 10; done""" +
            """; bash\\" """)


def gen_certs():
    ssh(HEAVY, "cd "+INSPATH+" && ./bin/insolar bootstrap --config scripts/insolard/bootstrap.yaml " +
        "--certificates-out-dir scripts/insolard/certs")
    run("mkdir -p /tmp/insolar-jepsen-configs/certs/ || true")
    run("mkdir -p /tmp/insolar-jepsen-configs/reusekeys/not_discovery/ || true")
    run("mkdir -p /tmp/insolar-jepsen-configs/reusekeys/discovery/ || true")
    scp_from(HEAVY, INSPATH+"/scripts/insolard/certs/*",
             "/tmp/insolar-jepsen-configs/certs/")
    scp_from(HEAVY, INSPATH+"/scripts/insolard/reusekeys/not_discovery/*",
             "/tmp/insolar-jepsen-configs/reusekeys/not_discovery/")
    scp_from(HEAVY, INSPATH+"/scripts/insolard/reusekeys/discovery/*",
             "/tmp/insolar-jepsen-configs/reusekeys/discovery/")
    for pod in LIGHTS+VIRTUALS:
        scp_to(pod, "/tmp/insolar-jepsen-configs/certs/*",
               INSPATH+"/scripts/insolard/certs/")
        scp_to(pod, "/tmp/insolar-jepsen-configs/reusekeys/not_discovery/*",
               INSPATH+"/scripts/insolard/reusekeys/not_discovery/")
        scp_to(pod, "/tmp/insolar-jepsen-configs/reusekeys/discovery/*",
               INSPATH+"/scripts/insolard/reusekeys/discovery/")


def deploy_insolar(skip_benchmark=False, use_postgresql=False):
    info("copying configs and fixing certificates for discovery nodes")
    pod_ips = k8s_get_pod_ips()

    if use_postgresql:
        deploy_postgresql(HEAVY, 'heavy')

    for pod in NODES:
        path = INSPATH+"/scripts/insolard/"
        pod_path = path+str(pod)
        ssh(pod, "mkdir -p "+pod_path)
        for k in pod_ips.keys():
            output = ssh_output(pod, "find "+path+" -type f -print " +
                " | grep -v .bak")
            debug(output)
            ssh(pod, "find "+path+" -type f -print " +
                " | grep -v .bak | xargs sed -i.bak 's/"+k.upper()+"/"+pod_ips[k]+"/g'")
        if pod == HEAVY:
            ssh(pod, "mkdir -p /tmp/heavy/tmp && mkdir -p /tmp/heavy/target && mkdir -p "+INSPATH+"/data")

        if pod == HEAVY and use_postgresql:
            scp_to(pod, "/tmp/insolar-jepsen-configs/insolar_" +
                   str(pod)+"_postgresql.yaml", pod_path + '/insolar_'+str(HEAVY)+".yaml")
        else:
            scp_to(pod, "/tmp/insolar-jepsen-configs/insolar_" +
                   str(pod)+".yaml", pod_path)
        scp_to(pod, "/tmp/insolar-jepsen-configs/pulsewatcher.yaml",
               INSPATH+"/pulsewatcher.yaml")
        scp_to(pod, "/tmp/insolar-jepsen-configs/pulse_exporter.proto",
               INSPATH+"/pulse_exporter.proto")

    info("Calling gen_certs()...")
    gen_certs()
    info("Calling run_genesis()...")
    run_genesis(use_postgresql)
    info("Calling start_insolar_net()...")
    start_insolar_net(NODES, pod_ips, step="starting",
                      skip_benchmark=skip_benchmark, use_postgresql=use_postgresql)
    info("==== Insolar started! ====")


def test_stop_start_virtuals_min_roles_ok(virtual_pods, pod_ips):
    virtual_pods_indexes = ""
    for pod in virtual_pods:
        virtual_pods_indexes = virtual_pods_indexes + str(pod) + "_"

    start_test(virtual_pods_indexes + "test_stop_start_virtuals_min_roles_ok")
    info("==== start/stop virtual at pods #" +
         virtual_pods_indexes+" test started ====")
    if len(VIRTUALS) - len(virtual_pods) < MIN_ROLES_VIRTUAL:
        msg = "TEST FAILED: test receive wrong parameter: " +\
              "amount of working virtual nodes must be more or equel to min roles in config (2 at the moment)"
        fail_test(msg)

    alive = wait_until_insolar_is_alive(
        pod_ips, NODES, step="before-killing-virtual")
    check_alive(alive)

    migrate_member(pod_ips, members_file=MEMBERS_FILE)

    ok, bench_out = run_benchmark(
        pod_ips, extra_args='-m --members-file=' + MEMBERS_FILE)
    check_benchmark(ok, bench_out)

    for pod in virtual_pods:
        info("Killing virtual on pod #"+str(pod))
        kill(pod, "insolard")

    alive_pod = [p for p in VIRTUALS if p not in virtual_pods][0]
    stay_alive_nods = [p for p in NODES if p not in virtual_pods]
    alive = wait_until_insolar_is_alive(
        pod_ips, stay_alive_nods, virtual_pod=alive_pod, step="virtual-down")
    check_alive(alive)

    info("Insolar is still alive. Re-launching insolard on pods #"+str(virtual_pods))
    for pod in virtual_pods:
        start_insolard(pod)

    alive = wait_until_insolar_is_alive(pod_ips, NODES, step="virtual-up")
    check_alive(alive)
    ok, out = check_balance_at_benchmark(
        pod_ips, extra_args='-m --members-file=' + MEMBERS_FILE + ' --check-all-balance'
    )
    check_benchmark(ok, out)

    ok, bench_out = run_benchmark(
        pod_ips, extra_args='-m --members-file=' + MEMBERS_FILE)
    check_benchmark(ok, bench_out)
    ok, out = check_balance_at_benchmark(
        pod_ips, extra_args='-m --members-file=' + MEMBERS_FILE + ' --check-all-balance'
    )
    check_benchmark(ok, out)

    info("==== start/stop virtual at pods #"+str(virtual_pods)+" passed! ====")
    stop_test()


def test_stop_start_virtuals_min_roles_not_ok(virtual_pods, pod_ips):
    virtual_pods_indexes = ""
    for pod in virtual_pods:
        virtual_pods_indexes = virtual_pods_indexes + str(pod) + "_"

    start_test(virtual_pods_indexes +
               "test_stop_start_virtuals_min_roles_not_ok")
    info("==== start/stop virtual at pods #" +
         virtual_pods_indexes+" test started ====")
    if len(VIRTUALS) - len(virtual_pods) >= MIN_ROLES_VIRTUAL:
        msg = "TEST FAILED: test receive wrong parameter: " +\
            "amount of working virtual nodes must be less then min roles in config (2 at the moment)"
        fail_test(msg)

    alive = wait_until_insolar_is_alive(
        pod_ips, NODES, step="before-killing-virtual")
    check_alive(alive)

    migrate_member(pod_ips, members_file=MEMBERS_FILE)

    ok, bench_out = run_benchmark(
        pod_ips, api_pod=LIGHTS[0], extra_args='-m --members-file=' + MEMBERS_FILE)
    check_benchmark(ok, bench_out)
    ok, out = check_balance_at_benchmark(
        pod_ips, extra_args='-m --members-file=' + MEMBERS_FILE + ' --check-all-balance'
    )
    check_benchmark(ok, out)

    info("Waiting until current pulse will be finalized...")
    wait_until_current_pulse_will_be_finalized()
    info("Current pulse is finalized!")

    for pod in virtual_pods:
        info("Killing virtual on pod #"+str(pod))
        kill(pod, "insolard")

    down = wait_until_insolar_is_down()
    check_down(down)
    info("Insolar is down. Re-launching nodes")
    start_insolar_net(NODES, pod_ips, step="virtual-up")

    ok, bench_out = run_benchmark(
        pod_ips, extra_args='-m --members-file=' + MEMBERS_FILE)
    check_benchmark(ok, bench_out)
    ok, out = check_balance_at_benchmark(
        pod_ips, extra_args='-m --members-file=' + MEMBERS_FILE + ' --check-all-balance'
    )
    check_benchmark(ok, out)

    info("==== start/stop virtual at pods #"+str(virtual_pods)+" passed! ====")
    stop_test()


def test_stop_start_lights(light_pods, pod_ips):
    light_pods_indexes = ""
    for pod in light_pods:
        light_pods_indexes = light_pods_indexes + str(pod) + "_"

    start_test(light_pods_indexes + "test_stop_start_light")
    info("==== start/stop light at pods #" +
         light_pods_indexes+" test started ====")
    alive = wait_until_insolar_is_alive(
        pod_ips, NODES, step="before-killing-light")
    check_alive(alive)

    migrate_member(pod_ips, members_file=MEMBERS_FILE)

    ok, bench_out = run_benchmark(
        pod_ips, extra_args='-m --members-file=' + MEMBERS_FILE)
    check_benchmark(ok, bench_out)
    ok, out = check_balance_at_benchmark(
        pod_ips, extra_args='-m --members-file=' + MEMBERS_FILE + ' --check-all-balance'
    )
    check_benchmark(ok, out)

    info("Wait for data to save on heavy (top sync pulse must change)")
    wait_until_current_pulse_will_be_finalized()
    info("Data was saved on heavy (top sync pulse changed)")

    for pod in light_pods:
        info("Killing light on pod #"+str(pod))
        kill(pod, "insolard")

    down = wait_until_insolar_is_down()
    check_down(down)
    info("Insolar is down. Re-launching nodes")
    start_insolar_net(NODES, pod_ips, step="light-up")

    ok, bench_out = run_benchmark(
        pod_ips, extra_args='-m --members-file=' + MEMBERS_FILE)
    check_benchmark(ok, bench_out)
    ok, out = check_balance_at_benchmark(
        pod_ips, extra_args='-m --members-file=' + MEMBERS_FILE + ' --check-all-balance'
    )
    check_benchmark(ok, out)

    info("==== start/stop light at pods #"+str(light_pods)+" passed! ====")
    stop_test()


def test_stop_start_heavy(heavy_pod, pod_ips, restore_from_backup=False):
    start_test("test_stop_start_heavy" +
               ("_restore_from_backup" if restore_from_backup else ""))
    info("==== start/stop heavy at pod #"+str(heavy_pod) +
         (" with restore from backup" if restore_from_backup else "")+" test started ====")
    alive = wait_until_insolar_is_alive(
        pod_ips, NODES, step="before-killing-heavy")
    check_alive(alive)

    migrate_member(pod_ips, members_file=MEMBERS_FILE)

    ok, bench_out = run_benchmark(
        pod_ips, extra_args='-m --members-file=' + MEMBERS_FILE)
    check_benchmark(ok, bench_out)
    ok, out = check_balance_at_benchmark(
        pod_ips, extra_args='-m --members-file=' + MEMBERS_FILE + ' --check-all-balance'
    )
    check_benchmark(ok, out)

    info("Wait for data to save on heavy (top sync pulse must change)")
    wait_until_current_pulse_will_be_finalized()
    info("Data was saved on heavy (top sync pulse changed)")

    info("Killing heavy on pod #"+str(heavy_pod))
    kill(heavy_pod, "insolard")

    down = wait_until_insolar_is_down()
    check_down(down)
    info("Insolar is down")
    if restore_from_backup:
        restore_heavy_from_backup(heavy_pod)
    info("Re-launching nodes")
    start_insolar_net(NODES, pod_ips, step="heavy-up")

    ok, bench_out = run_benchmark(
        pod_ips, extra_args='-m --members-file=' + MEMBERS_FILE)
    check_benchmark(ok, bench_out)
    ok, out = check_balance_at_benchmark(
        pod_ips, extra_args='-m --members-file=' + MEMBERS_FILE + ' --check-all-balance'
    )
    check_benchmark(ok, out)

    info("==== start/stop heavy at pod #"+str(heavy_pod) +
         (" with restore from backup" if restore_from_backup else "")+" passed! ====")
    stop_test()


def is_benchmark_alive(pod):
    output = ssh_output(pod, "ps aux | grep [b]enchmark")
    info("is_benchmark_alive: " + output)
    return len(output) != 0


def test_kill_heavy_under_load(heavy_pod, pod_ips, restore_from_backup=False):
    start_test("test_kill_heavy_under_load" +
               ("_restore_from_backup" if restore_from_backup else ""))
    info("==== kill heavy under load at pod #"+str(heavy_pod) +
         (" with restore from backup" if restore_from_backup else "")+" test started ====")
    alive = wait_until_insolar_is_alive(
        pod_ips, NODES, step="before-killing-heavy")
    check_alive(alive)

    info("Create several members with benchmark")
    migrate_member(pod_ips, members_file=MEMBERS_FILE)
    ok, bench_out = run_benchmark(
        pod_ips, extra_args='-m --members-file=' + MEMBERS_FILE)
    check_benchmark(ok, bench_out)
    info("Wait for data to save on heavy (top sync pulse must change)")
    wait_until_current_pulse_will_be_finalized()
    info("Starting benchmark on these members in the background, wait several transfer to pass")
    ok, bench_out = run_benchmark(pod_ips, r=10000, timeout=100, background=True,
                                  extra_args='-b -m --members-file=' + MEMBERS_FILE)

    info("Bench run output: " + bench_out)
    wait(20)

    if not is_benchmark_alive(heavy_pod):
        fail_test("Benchmark must be alive")

    info("Killing heavy on pod #"+str(heavy_pod))
    kill(heavy_pod, "insolard")

    down = wait_until_insolar_is_down()
    check_down(down)
    info("Insolar is down")

    info("Killing benchmark on pod #"+str(heavy_pod))
    kill(heavy_pod, "benchmark")

    if restore_from_backup:
        restore_heavy_from_backup(heavy_pod)

    info("Re-launching nodes")
    start_insolar_net(NODES, pod_ips, step="heavy-up")

    for n in range(20):
        ok, check_out = check_balance_at_benchmark(
            pod_ips, extra_args='-m --members-file=' +
            MEMBERS_FILE + ' --check-total-balance'
        )
        if not ok:
            info("Benchmark reply: " + check_out)
            wait(5)
        else:
            break

    check_benchmark(
        ok, 'Error while checking total balance with benchmark (waited for 100s): ' + check_out)

    info("==== kill heavy under load at pod #"+str(heavy_pod) +
         (" with restore from backup" if restore_from_backup else "")+" passed! ====")
    stop_test()


def test_kill_backupprocess(heavy_pod, pod_ips, restore_from_backup=False, create_backup_from_existing_db=False):
    start_test("test_kill_backupprocess" +
               ("_restore_from_backup" if restore_from_backup else "") +
               ("_created_backup_from_existing_db" if create_backup_from_existing_db else ""))
    info("==== kill backupmanager " +
         ("with restore from backup " if restore_from_backup else "") +
         ("and create backup from existing DB " if create_backup_from_existing_db else "") + "test started ====")
    alive = wait_until_insolar_is_alive(
        pod_ips, NODES, step="before-killing-backupmanager")
    check_alive(alive)

    info("Running benchmark and trying to kill backupmanager on pod #"+str(heavy_pod))

    # Note: when backuping script starts it saves its pid to /tmp/heavy/backup.pid
    ssh(heavy_pod, "tmux new-session -d -s backupprocess-killer " +
        """\\"while true; do cat /tmp/heavy/backup.pid | xargs kill -9 ;  sleep 0.1; done """ +
        """; bash\\" """)

    ok, bench_out = run_benchmark(pod_ips, r=100, timeout=100)
    check(not ok, "Benchmark should fail while killing backupmanager (increase -c or -r?), but it was successfull:\n" + bench_out)

    info("Shutting down backupprocess-killer")
    ssh(heavy_pod, "tmux kill-session -t backupprocess-killer")

    down = wait_until_insolar_is_down()
    check_down(down)
    info("Insolar is down")

    if restore_from_backup:
        restore_heavy_from_backup(heavy_pod)
    else:
        if create_backup_from_existing_db:
            ssh(heavy_pod, "cd "+INSPATH +
                " && (rm -r ./heavy_backup || true) && cp -r ./data ./heavy_backup")

    info("Re-launching nodes")
    start_insolar_net(NODES, pod_ips, step="heavy-up")

    ok, bench_out = run_benchmark(pod_ips)
    check_benchmark(ok, bench_out)

    info("==== kill backupprocess " +
         ("with restore from backup " if restore_from_backup else "") +
         ("and create backup from existing DB " if create_backup_from_existing_db else "") + "passed! ====")
    stop_test()


def test_network_slow_down_speed_up(pod_ips):
    start_test("test_network_slow_down_speed_up")
    info("==== slow down / speed up network test started ====")
    for pod in ALL_PODS:
        set_network_speed(pod, SLOW_NETWORK_SPEED)
    alive = wait_until_insolar_is_alive(pod_ips, NODES, step="slow-network")
    check_alive(alive)
    for pod in ALL_PODS:
        set_network_speed(pod, FAST_NETWORK_SPEED)
    alive = wait_until_insolar_is_alive(pod_ips, NODES, step="fast-network")
    check_alive(alive)
    info("==== slow down / speed up network test passed! ====")
    stop_test()


def test_virtuals_slow_down_speed_up(pod_ips):
    start_test("test_virtuals_slow_down_speed_up")
    info("==== slow down / speed up virtuals test started ====")
    for pod in VIRTUALS:
        set_network_speed(pod, SLOW_NETWORK_SPEED)
    alive = wait_until_insolar_is_alive(pod_ips, NODES, step="slow-virtuals")
    check_alive(alive)
    for pod in VIRTUALS:
        set_network_speed(pod, FAST_NETWORK_SPEED)
    alive = wait_until_insolar_is_alive(pod_ips, NODES, step="fast-virtuals")
    check_alive(alive)
    info("==== slow down / speed up virtuals test passed! ====")
    stop_test()


def test_small_mtu(pod_ips):
    start_test("test_small_mtu")
    info("==== small mtu test started ====")
    for pod in ALL_PODS:
        set_mtu(pod, SMALL_MTU)
    alive = wait_until_insolar_is_alive(pod_ips, NODES, step="small-mtu")
    check_alive(alive)
    for pod in ALL_PODS:
        set_mtu(pod, NORMAL_MTU)
    alive = wait_until_insolar_is_alive(pod_ips, NODES, step="noraml-mtu")
    check_alive(alive)
    info("==== small mtu test passed! ====")
    stop_test()


def test_stop_start_pulsar(pod_ips, test_num):
    start_test("test_stop_start_pulsar")
    info("==== start/stop pulsar test started ====")
    info("Killing pulsard")
    kill(PULSAR, "pulsard")

    down = wait_until_insolar_is_down()
    check_down(down)
    info("Insolar is down. Re-launching net")

    info("Starting pulsar")
    start_pulsard()

    start_insolar_net(NODES, pod_ips, step="pulsar-up")
    info("==== start/stop pulsar test passed! ====")
    stop_test()


def test_netsplit_single_virtual(pod, pod_ips):
    start_test("test_netsplit_single_virtual")
    info("==== netsplit of single virtual at pod#"+str(pod)+" test started ====")
    alive_pod = [p for p in VIRTUALS if p != pod][0]
    alive = wait_until_insolar_is_alive(
        pod_ips, NODES, step="before-netsplit-virtual")
    check_alive(alive)
    info("Emulating netsplit that affects single pod #" +
         str(pod)+", testing from pod #"+str(alive_pod))
    create_simple_netsplit(pod, pod_ips)
    stay_alive_nods = NODES.copy()
    stay_alive_nods.remove(pod)
    alive = wait_until_insolar_is_alive(
        pod_ips, stay_alive_nods, virtual_pod=alive_pod, step="netsplit-virtual")
    check_alive(alive)
    info("Insolar is alive during netsplit")
    # insolard suppose to die in case of netsplit
    for i in range(0, 10):
        if not insolar_is_alive_on_pod(pod):
            break
        info('Insolard is not terminated yet at pod#'+str(pod))
        wait(10)
    check(not insolar_is_alive_on_pod(pod),
          "Insolar must be down on pod %s, but its up" % pod)
    info('Fixing netsplit')
    fix_simple_netsplit(pod, pod_ips)
    info('Restarting insolard at pod#'+str(pod))
    start_insolard(pod)
    alive = wait_until_insolar_is_alive(
        pod_ips, NODES, virtual_pod=alive_pod, step="netsplit-virtual-relaunched")
    check_alive(alive)
    info("==== netsplit of single virtual at pod#"+str(pod)+" test passed! ====")
    stop_test()


def clear_logs_after_repetition_and_restart():
    info("Stop nodes and clear logs before next repetition")
    for node in NODES:
        kill(node, "insolard")
    kill(PULSAR, "pulsard")

    down = wait_until_insolar_is_down()
    check_down(down)
    info("Insolar is down")
    info("Clear logs before next repetition")
    for pod in NODES:
        ssh(pod, "cd " + INSPATH + " && rm insolard_*.log.gz")

    info("Starting pulsar for next repetition")
    start_pulsard()
    info("Re-launching nodes for next repetition")
    start_insolar_net(NODES, pod_ips)
    ok, bench_out = run_benchmark(pod_ips)
    check_benchmark(ok, bench_out)


# check_abandoned_requests calculates abandoned requests leak.
#
# nattempts - number of attempts for checking abandoned requests metric from nodes.
# step - time in seconds between two attempts.
# verbose - flag for additional logging.
def check_abandoned_requests_not_increasing(nattempts=10, step=15, verbose=False):
    start_test("check_abandoned_requests")
    info("==== start/stop check_abandoned_requests test started ====")

    # Dict with count of abandoned metric. (key - <node_and_metric_mane>, value - <count>).
    # Example: <10.1.0.179:insolar_requests_abandoned{role="heavy_material"} 20>,
    #          <10.1.0.180:insolar_requests_abandoned{role="light_material"} 35>,
    #          ...
    abandoned_data = {}
    # Difference of abandoned requests count in one step.
    abandoned_delta = 0
    errors = ""

    for attempt in range(1, nattempts+1):
        abandoned_delta = 0
        time.sleep(step)
        # node id for investigations
        i = 0
        abandoned_raw_data = get_abandones_count_from_nodes()

        if len(abandoned_raw_data) == 0:
            continue

        for line in abandoned_raw_data.split("\n"):
            kv = line.split()
            if len(kv) <= 1:
                # set starting value
                kv.insert(1, 0)

            # key for abandoned_data dict, consists from <node_id:node_ip>
            node = str(i) + ":" + kv[0]
            count = int(kv[1])                 # value for abandoned_data dict.
            if node in abandoned_data and count > abandoned_data[node]:
                abandoned_delta += count - abandoned_data[node]
                errors += "Attempt: " + str(attempt) + ". Abandoned increased in " + node + \
                          ". Old:" + \
                    str(abandoned_data[node]) + \
                    ", New:" + str(count) + os.linesep

            abandoned_data[node] = count
            i += 1

        if verbose:
            info("Attempt " + str(attempt) +
                 ". Abandoned requests delta: " + str(abandoned_delta))

    # If abandoned_delta is 0
    # we assume, that all of them was processed.
    if abandoned_delta != 0:
        info(errors)
    check(abandoned_delta == 0, "Unprocessed Abandoned-requests count IS NOT ZERO.")

    info("==== start/stop check_abandoned_requests test passed! ====")
    stop_test()

# get_abandones_count_from_nodes returns list of abandoned requests metric from all nodes:
#   10.1.0.179:insolar_requests_abandoned{role="heavy_material"} 1
#   10.1.0.180:insolar_requests_abandoned{role="light_material"} 20
#   ...


def get_abandones_count_from_nodes():
    abandoned_data = ssh_output(
        HEAVY, 'cd ' + INSPATH + ' && ./jepsen-tools/collect_abandoned_metrics.py')
    debug(abandoned_data)
    return abandoned_data


def check_dependencies():
    info("Checking dependencies...")
    for d in DEPENDENCIES:
        run('which ' + d)
    info("All dependencies found.")


def upload_tools(pod, pod_ips):
    info("Uploading tools ...")
    ips = ' '.join(pod_ips.values())
    ssh(pod, "mkdir -p "+INSPATH+"/jepsen-tools/ && echo " +
        ips + " > "+INSPATH+"/jepsen-tools/pod_ips")
    scp_to(pod, "./jepsen-tools/*", INSPATH+"/jepsen-tools/")


parser = argparse.ArgumentParser(
    description='Test Insolar using Jepsen-like tests')

parser.add_argument(
    '-d', '--debug', action="store_true",
    help='enable debug output')
parser.add_argument(
    '-s', '--skip-all-tests', action="store_true",
    help='skip all tests, check only deploy procedure')
parser.add_argument(
    '-m', '--minimum-tests', action="store_true",
    help='run minimal required tests set')
parser.add_argument(
    '-r', '--repeat', metavar='N', type=int, default=1,
    help='number of times to repeat tests')
parser.add_argument(
    '-p', '--postgresql', action="store_true",
    help='Use PostgreSQL for storing data on Heavy istead of Badger')
parser.add_argument(
    '--redeploy-observer', action="store_true",
    help='re-deploy observer on running pods; valid only when -o and -s flags are used')
parser.add_argument(
    '--keep-database', metavar='K', type=str,
    help='Whether to keep the database during the re-deploy of observer')
parser.add_argument(
    '-n', '--namespace', metavar='X', type=str, default="default",
    help='exact k8s namespace to use')
parser.add_argument(
    '-c', '--ci', action="store_true",
    help='use CI-friendly configuration')
parser.add_argument(
    '-i', '--image', metavar='IMG', type=str, required=True,
    help='Docker image to test')
parser.add_argument(
    '-l', '--launch-only', action="store_true",
    help='Launch insolar on running pods, i.e. restart after failed tests (hint: use with `-i dummy`)')
parser.add_argument(
    '-o', '--others-path', metavar='P', type=str, default="",
    help='Path to cloned reposities of observer and Java API microservices (closed-source projects)')
parser.add_argument(
    '-po', '--public-observer', action="store_true",
    help='build public observer version')

args = parser.parse_args()
NAMESPACE = args.namespace
DEBUG = args.debug
start_test("prepare")
check_dependencies()

if args.skip_all_tests and args.others_path and args.redeploy_observer:
    if args.keep_database != 'true' and args.keep_database != 'false':
        info("When using --redeploy-observer you should specify `--keep-database true` or `--keep-database false`")
        sys.exit(1)
    keep_database = (args.keep_database == 'true')
    info("=== Re-deploying observer on running pods, keep_database = "+str(keep_database)+"... ===")
    POD_NODES = k8s_get_pod_nodes()
    wait_until_ssh_is_up_on_pods()
    deploy_observer(args.others_path, keep_database=keep_database, public=args.public_observer)
    notify("Observer re-deployed!")
    sys.exit(0)

if args.launch_only:
    POD_NODES = k8s_get_pod_nodes()
    wait_until_ssh_is_up_on_pods()
    pod_ips = k8s_get_pod_ips()
    info("=== Launching pulsard... ===")
    start_pulsard()
    info("=== Launching insolar network... ===")
    start_insolar_net(NODES, pod_ips, step="starting",
                      skip_benchmark=args.skip_all_tests)
    info("=== Insolar launched! ===")
    sys.exit(0)

k8s_yaml = "jepsen-pods.yaml"
info("Generating "+k8s_yaml)
k8s_gen_yaml(k8s_yaml, args.image, "IfNotPresent" if args.ci else "Never")
k8s_stop_pods_if_running()
k8s_start_pods(k8s_yaml)
POD_NODES = k8s_get_pod_nodes()
wait_until_ssh_is_up_on_pods()
pod_ips = k8s_get_pod_ips()
upload_tools(HEAVY, pod_ips)
prepare_configs()
deploy_pulsar()
deploy_insolar(skip_benchmark=args.skip_all_tests, use_postgresql = args.postgresql)
if args.others_path:
    deploy_observer_deps()
    deploy_observer(args.others_path, public=args.public_observer)
stop_test()

if args.skip_all_tests:
    notify("Deploy checked, skipping all tests")
    sys.exit(0)

# TODO: we don't actually need this delay but there is a slight unresolved issue
# that requires it when PostgreSQL backend is used. This is a temporary workaround
# to make sure all other tests pass. See MN-126
info("Waiting until current pulse will be finalized.")
wait_until_current_pulse_will_be_finalized()
info("Current pulse is finalized. Executing migrate_member()...")

migrate_member(pod_ips, members_file=OLD_MEMBERS_FILE)
ok, bench_out = run_benchmark(
    pod_ips, extra_args="-m --members-file=" + OLD_MEMBERS_FILE)
check_benchmark(ok, bench_out)
members_creted_at = time.time()
pulse_when_members_created = current_pulse()

info("Wait for data to save on heavy (top sync pulse must change)")
wait_until_current_pulse_will_be_finalized()
info("Data was saved on heavy (top sync pulse changed)")

tests = [
    # lambda: test_network_slow_down_speed_up(pod_ips), # TODO: doesn't work well on CI, see INS-3695
    # lambda: test_virtuals_slow_down_speed_up(pod_ips), TODO: this test doesn't pass currently, see INS-3688
    # lambda: test_small_mtu(pod_ips), # TODO: this test doesn't pass currently, see INS-3689
    lambda: test_stop_start_pulsar(pod_ips, test_num),
    # TODO: sometimes test_netsplit_single_virtual doesn't pass, see INS-3687
    # Temporary skipped until release (15 Jan).
    # This test does not affects mainnet scope but can hide other problems.
    # This is still a major problem!
    # lambda: test_netsplit_single_virtual(VIRTUALS[0], pod_ips),
    lambda: test_stop_start_virtuals_min_roles_ok(VIRTUALS[:1], pod_ips),
    lambda: test_stop_start_virtuals_min_roles_ok(VIRTUALS[:2], pod_ips),
    lambda: test_stop_start_virtuals_min_roles_not_ok(VIRTUALS, pod_ips),
    lambda: test_stop_start_virtuals_min_roles_not_ok(VIRTUALS[1:], pod_ips),
    lambda: test_stop_start_lights([LIGHTS[0]], pod_ips),
    lambda: test_stop_start_lights([LIGHTS[1], LIGHTS[2]], pod_ips),
    lambda: test_stop_start_lights(LIGHTS, pod_ips),
    lambda: test_stop_start_heavy(HEAVY, pod_ips),
    lambda: test_kill_heavy_under_load(HEAVY, pod_ips),
]

if not args.postgresql:
    tests += [
    lambda: test_stop_start_heavy(HEAVY, pod_ips, restore_from_backup=True),
    lambda: test_kill_backupprocess(HEAVY, pod_ips, restore_from_backup=True),
    lambda: test_kill_heavy_under_load(
        HEAVY, pod_ips, restore_from_backup=True),
    lambda: test_kill_backupprocess(HEAVY, pod_ips),
    lambda: test_kill_backupprocess(
        HEAVY, pod_ips, create_backup_from_existing_db=True),
    ]

minimum_tests = [
    lambda: test_stop_start_pulsar(pod_ips, test_num),
    lambda: test_stop_start_virtuals_min_roles_ok(VIRTUALS[:1], pod_ips),
    # Temporary disable restore_from_backup until the test will be stabilized -- Aleksander Alekseev
    # lambda: test_stop_start_heavy(HEAVY, pod_ips, restore_from_backup=True),
    lambda: test_stop_start_heavy(HEAVY, pod_ips),
]

for test_num in range(0, args.repeat):
    tests_to_run = minimum_tests if args.minimum_tests else tests
    random.shuffle(tests_to_run)
    for t in tests_to_run:
        t()
    check_abandoned_requests_not_increasing(verbose=True)
    info("ALL TESTS PASSED: "+str(test_num+1)+" of "+str(args.repeat))

    # The following test should be executed after the rest of the tests
    nattempt = 0
    while True:
        nattempt += 1
        check(nattempt < LIGHT_CHAIN_LIMIT*3, "Timeout!")
        cp = current_pulse()
        pulses_pass = (cp - pulse_when_members_created)//PULSE_DELTA
        info("[Attempt "+str(nattempt)+"/"+str(LIGHT_CHAIN_LIMIT*3)+"] current pulse = "+str(cp) +
             ", pulse_when_members_created = "+str(pulse_when_members_created)+", pulses_pass = "+str(pulses_pass))
        if pulses_pass >= LIGHT_CHAIN_LIMIT:
            info("Success!")
            break
        wait(PULSE_DELTA/2)

    info("Make calls to members, created at the beginning: " +
         str(pulses_pass) + " pulses ago")
    ok, out = check_balance_at_benchmark(
        pod_ips, extra_args="-m --members-file=" +
        OLD_MEMBERS_FILE + " --check-members-balance"
    )
    check_benchmark(ok, out)
    ok, bench_out = run_benchmark(
        pod_ips, extra_args="-m --members-file=" + OLD_MEMBERS_FILE)
    check_benchmark(ok, bench_out)
    if test_num != args.repeat-1:
        clear_logs_after_repetition_and_restart()

notify("Test completed!")
info("Stop nodes")
for node in NODES:
    kill(node, "insolard")
kill(PULSAR, "pulsard")
