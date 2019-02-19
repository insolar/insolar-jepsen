#!/usr/bin/env python3
# vim: set ai et ts=4 sw=4:

import os
import sys
import subprocess
import tempfile

START_PORT = 32000

def run(cmd):
    code = subprocess.call(cmd, shell=True)
    if code != 0:
        print("Command `%s` returned non-zero status: %d" %
              (cmd, code))
        sys.exit(1)

def ssh(node, cmd):
	run("ssh -o 'StrictHostKeyChecking no' -i ./ssh-keys/id_rsa -p"+\
        str(START_PORT + node)+""" gopher@localhost "bash -c 'source ./.bash_profile ; """+\
        cmd + """ '" """)

ssh(1, 'id')
