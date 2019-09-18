#!/usr/bin/python3
import os
import subprocess


def run(cmd):
    # print(cmd)
    result = subprocess.run([cmd], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
    if result.stderr is not None:
        print(result.stderr)
    return result.stdout.decode('utf-8')


def get_ips():
    dir_path = os.path.dirname(os.path.realpath(__file__))
    fname = dir_path + "/pod_ips"
    f = open(fname, 'r')
    ips_str = f.readline().rstrip()
    res = ips_str.split(' ')
    f.close()
    return res


result = ""
port = "8080"
metric_name = "insolar_requests_abandoned{"
ips = get_ips()
for ip in ips:
    cmd = "curl -s " + ip + ":" + port + "/metrics | grep " + metric_name
    metric = run(cmd)
    result += ip + ":" + str(metric).rstrip() + os.linesep

print(result.rstrip())
