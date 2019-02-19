#!/usr/bin/env python3
# vim: set ai et ts=4 sw=4:

import os
import sys
import subprocess
import argparse

START_PORT = 32000
INSPATH = "go/src/github.com/insolar/insolar"

def run(cmd):
    print("RUNNING: "+cmd)
    code = subprocess.call(cmd, shell=True)
    if code != 0:
        print("Command `%s` returned non-zero status: %d" %
              (cmd, code))
        sys.exit(1)

def ssh(node, cmd):
	run("ssh -o 'StrictHostKeyChecking no' -i ./ssh-keys/id_rsa -p"+\
        str(START_PORT + node)+""" gopher@localhost "bash -c 'source ./.bash_profile ; """+\
        cmd + """ '" 2>/dev/null""")

def scp_to(node, lpath, rpath, flags=''):
    run("scp -o 'StrictHostKeyChecking no' -i ./ssh-keys/id_rsa -P"+\
        str(START_PORT + node)+" "+flags+" " + lpath + " gopher@localhost:"+rpath+" 2>/dev/null")

def scp_from(node, rpath, lpath, flags=''):
    run("scp -o 'StrictHostKeyChecking no' -i ./ssh-keys/id_rsa -P"+\
        str(START_PORT + node)+" " + flags + " gopher@localhost:"+rpath+" "+lpath+" 2>/dev/null")

parser = argparse.ArgumentParser(description='Execute a simple "node down/node up" Jepsen test')
parser.add_argument(
    '-s', '--skip-build', action="store_true",
    help='skip an expensice `build` step and use cached binaries')
args = parser.parse_args()

if not args.skip_build:
    # building insolar from master on all nodes
    # TODO: run in parallel
    for node in range(1, 5+1):
        ssh(node, "cd "+INSPATH+" && "+\
            "git checkout master && git pull && make clean build")

# copying `data` directory from node 1 to nodes 2...5
run("rm -r /tmp/insolar-jepsen-data || true")
scp_from(1, INSPATH+"/data", "/tmp/insolar-jepsen-data", flags='-r')
for node in range(2, 5+1):
    scp_to(node, "/tmp/insolar-jepsen-data", INSPATH+"/data", flags='-r')

run("rm -r /tmp/insolar-jepsen-configs || true")
run("cp -r ./config-templates /tmp/insolar-jepsen-configs")
# TODO: replace IPs

ssh(1, "mkdir -p "+INSPATH+"/scripts/insolard/configs/")
scp_to(1, "/tmp/insolar-jepsen-configs/pulsar.yaml", INSPATH+"/pulsar.yaml")
scp_to(1, "/tmp/insolar-jepsen-configs/bootstrap_keys.json", INSPATH+"/scripts/insolard/configs/bootstrap_keys.json")
ssh(1, "cd " + INSPATH + " && ./bin/pulsard -c pulsar.yaml")
