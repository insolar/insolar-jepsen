#!/usr/bin/env python3
# vim: set ai et ts=4 sw=4:

import os
import sys
import subprocess
import tempfile

START_PORT = 32000

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


ssh(1, 'echo "aaa" > test.txt')
scp_from(1, "test.txt", "/tmp/test.txt")
scp_to(1, "/tmp/test.txt", "test2.txt")
ssh(1, 'cat test2.txt')

run("rm -r /tmp/insolar-jepsen-data || true")
scp_from(1, "go/src/github.com/insolar/insolar/data", "/tmp/insolar-jepsen-data", flags='-r')
scp_to(2, "/tmp/insolar-jepsen-data", "go/src/github.com/insolar/insolar/data", flags='-r')
scp_to(3, "/tmp/insolar-jepsen-data", "go/src/github.com/insolar/insolar/data", flags='-r')
scp_to(4, "/tmp/insolar-jepsen-data", "go/src/github.com/insolar/insolar/data", flags='-r')
scp_to(5, "/tmp/insolar-jepsen-data", "go/src/github.com/insolar/insolar/data", flags='-r')
