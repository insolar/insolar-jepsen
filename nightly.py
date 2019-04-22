#!/usr/bin/env python3

import os
import sys
import subprocess
import argparse

def run(cmd):
    code = subprocess.call(cmd, shell=True)
    if code != 0:
        print("Command `%s` returned non-zero status: %d" %
              (cmd, code))
        sys.exit(1)

def get_output(cmd):
    data = subprocess.check_output(cmd, shell=True)
    data = data.decode('utf-8').strip()
    return data

parser = argparse.ArgumentParser(description='Run nightly Insolar Jepsen-like tests')
parser.add_argument(
    '-b', '--branch', metavar='B', type=str, default='master',
    help='git branch name')
parser.add_argument(
    '-r', '--repeat', metavar='N', type=int, default=100,
    help='number of times to repeat tests')
parser.add_argument(
    '-s', '--slack', metavar='H', type=str, required=True,
    help='slack hook string (it looks like base64 string)')
parser.add_argument(
    '-l', '--logdir', metavar='DIR', type=str, required=True,
    help='path to the directory where logfiles will be saved')
parser.add_argument(
    '-u', '--url', metavar='URL', type=str, required=True,
    help='URL where saved logfiles will be accessible')
args = parser.parse_args()

tests_passed = False
try:
    date = get_output('date +%Y-%m-%d')
    logfile_name = 'jepsen-' + date + '.txt'
    logfile_fullname = args.logdir + '/' + logfile_name
    run('echo "=== BUILDING BRANCH '+args.branch+' ===" | tee -a '+logfile_fullname)
    run('./build-docker.py '+args.branch+' | tee -a '+logfile_fullname)
    run('echo "==== RUNNING TESTS '+str(args.repeat)+' TIMES ===" | tee -a '+logfile_fullname)
    run('./run-test.py -i insolar-jepsen:latest -r '+args.repeat+' | tee -a '+logfile_fullname)
    tests_passed = True
except Exception as e:
    print("ERROR:")
    print(str(e))

print("Test passed: "+str(tests_passed))
