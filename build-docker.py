#!/usr/bin/env python3
# vim: set ai et ts=4 sw=4:

import os
import os.path
import sys
import subprocess
import time
import argparse

# requires insolar-base image
#
# if you have it, you could build image manually, just run:
#
#   docker build -t insolar-jepsen .
#
# simple image test image, it shouldn't throw any errors:
#
# docker run --rm -it insolar-jepsen

from contextlib import contextmanager

def parse_args() -> dict:
    parser = argparse.ArgumentParser(description='Build jepsen docker image.')
    parser.add_argument('--insolar-sources', '-s', dest='co_dir', type=str, required=True,
        help='path where to checkout insolar sources')

    checkout_group = parser.add_mutually_exclusive_group(required=True)

    checkout_group.add_argument('--disable-checkout', action='store_true',
        help='just use insolar sources dir')

    git_group = checkout_group.add_mutually_exclusive_group()
    git_group.add_argument('--branch', '-b', type=str, help='insolar branch')
    git_group.add_argument('--tag', '-t', type=str, help='insolar tag')

    return parser.parse_args()

# main logic
def main():
    args = parse_args()

    if not args.disable_checkout:
        git_ref = args.branch or args.tag
        is_tag = bool(args.tag)
        log("Going to checkout {} {}".format(
            {True: "tag", False: "branch"}[is_tag], git_ref))
        time.sleep(2)
        checkout_insolar(args.co_dir, git_ref, is_tag)

    build_insolar_base_image(args.co_dir)
    build_jepsen_image()
    notify("Docker build completed")

def checkout_insolar(code_dir: str, ref: str, is_tag: bool):
    with timing("Fetch git took"):
        if not os.path.isdir(code_dir):
            run(f"git clone https://github.com/insolar/insolar.git {code_dir}")
        with cd(code_dir):
            log(f"git fetch and checkout {ref} in {code_dir}")
            run(f"git fetch --prune")
            run(f"git checkout {ref}")
            if not is_tag:
                run(f"git pull")

def build_insolar_base_image(code_dir: str):
    with timing("Build base image took"):
        with cd(code_dir):
            run(f"make docker_base_build")

def build_jepsen_image():
    with timing("Build jepsen image took"):
        run("docker build -t insolar-jepsen .")

# helpers
def notify(message):
    run("""which osascript && osascript -e 'display notification " """ + message + """ " with title "Jepsen"' || true""")

def run(cmd):
    log("CALL: "+cmd)
    code = subprocess.call(cmd, shell=True)
    if code != 0:
        log("Command `%s` returned non-zero status: %d" % (cmd, code))
        sys.exit(1)

def log(s: str):
    print("JEPSEN BUILDER>", s)

@contextmanager
def cd(directory):
    owd = os.getcwd()
    try:
       os.chdir(directory)
       yield directory
    finally:
       os.chdir(owd)

@contextmanager
def timing(description: str) -> None:
    start = time.time()
    yield
    diff = time.time() - start
    m, s = int(diff/60), int(diff % 60)
    log(f"{description}: {m} min {s} sec")


main()