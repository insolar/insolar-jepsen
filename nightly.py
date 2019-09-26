#!/usr/bin/env python3
# vim: set ai et ts=4 sw=4:

import os
import subprocess
import argparse
import time
import calendar
import re


def run(cmd):
    code = subprocess.call(['/bin/bash', '-o', 'pipefail', '-c', cmd])
    if code != 0:
        raise RuntimeError("Command `%s` returned non-zero status: %d" %
                           (cmd, code))


def get_output(cmd):
    data = subprocess.check_output(cmd, shell=True)
    data = data.decode('utf-8').strip()
    return data


parser = argparse.ArgumentParser(
    description='Run nightly Insolar Jepsen-like tests')
parser.add_argument(
    '-b', '--branch', metavar='B', type=str, default='master',
    help='git branch name (default: master)')
parser.add_argument(
    '-r', '--repeat', metavar='N', type=int, default=100,
    help='number of times to repeat tests (default: 100)')
parser.add_argument(
    '-c', '--channel', metavar='C', type=str, default='#dev-backend',
    help='slack channel (default: #dev-backend)')
parser.add_argument(
    '-e', '--emoji', metavar='E', type=str, default='aphyr',
    help='message emoji (default: aphyr)')
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
date = "FAILED_TO_GET_DATE"
try:
    date = get_output('date +%Y%m%d%H%M00')
except Exception as e:
    print("ERROR:")
    print(str(e))

logfile_name = 'jepsen-' + date + '.txt'
logfile_fullname = args.logdir + '/' + logfile_name

try:
    run('echo "=== BUILDING BRANCH '+args.branch +
        ' ===" | tee -a '+logfile_fullname)
    run('./build-docker.py '+args.branch+' 2>&1 | tee -a '+logfile_fullname)
    run('echo "==== RUNNING TESTS '+str(args.repeat) +
        ' TIMES ===" | tee -a '+logfile_fullname)
    run('./run-test.py -i insolar-jepsen:latest -r ' +
        str(args.repeat)+' 2>&1 | tee -a '+logfile_fullname)
    tests_passed = True
except Exception as e:
    print("ERROR:")
    print(str(e))

podlogs_name = 'jepsen-' + date + '.tgz'
podlogs_fullname = args.logdir + '/' + podlogs_name

try:
    run('echo "=== AGGREGATING LOGS TO ' +
        podlogs_fullname+' ===" | tee -a '+logfile_fullname)
    run('./aggregate-logs.py /tmp/jepsen-'+date)
    run('gunzip /tmp/jepsen-'+date+'/*/*.log.gz || true')
    run('tar -cvzf '+podlogs_fullname+' /tmp/jepsen-'+date)
    run('rm -r /tmp/jepsen-'+date)

    run('echo "=== CLEANING UP '+args.logdir+' ===" | tee -a '+logfile_fullname)
    now = int(time.time())
    os.chdir(args.logdir)
    for fname in os.listdir("."):
        m = re.search("jepsen-(\d{4}\d{2}\d{2})", fname)
        ftime = calendar.timegm(time.strptime(m.group(1), "%Y%m%d"))
        ndays = int((now - ftime) / (60 * 60 * 24))
        delete = ndays > 15
        run(' echo "File: ' + fname + ', ndays: ' + str(ndays) +
            ', delete: ' + str(delete) + '" | tee -a '+logfile_fullname)
        if delete:
            os.unlink(fname)
except Exception as e:
    print("ERROR:")
    print(str(e))

print("Test passed: "+str(tests_passed))
message = 'PASSED' if tests_passed else 'FAILED'
message = 'Nightly Jepsen-like tests '+message +\
          '. Log: '+args.url+'/'+logfile_name +\
          ' Pod logs: '+args.url+'/'+podlogs_name
cmd = 'curl -X POST --data-urlencode \'payload={"channel": "'+args.channel +\
    '", "username": "aphyr", "text": "'+message +\
    '", "icon_emoji": ":'+args.emoji +\
    ':"}\' https://hooks.slack.com/services/'+args.slack
print("EXECUTING: "+cmd)
run(cmd)
