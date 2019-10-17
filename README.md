# insolar-jepsen

Jepsen-like tests for Insolar.

**Requirements:** docker, kubectl, jq, python3.

If you are using Docker Desktop, please note, that by default it uses rather strict resource limits. You might want to change these limits in Preferences... -> Advanced tab.

Usage:

```
# Make sure private key is readable only by current user
chmod 600 ./base-image/id\_rsa

# Label current node: jepsen=true
kubectl label node docker-desktop jepsen=true

# Install Python dependencies
mkvirtualenv insolar-jepsen
pip3 install -r requirements.txt

# to build the base image:
cd base-image && docker build --no-cache -t tsovak/insolar-jepsen-base . && cd ..

# to build the branch image:
./build-docker.py branch-name

# run tests (use --help flag to see all arguments)
./run-test.py -i insolar-jepsen:latest
```

After the test:

```
# To login to `jepsen-1` pod:
ssh -o 'StrictHostKeyChecking no' -i ./base-image/id\_rsa -p 32001 gopher@localhost

# To attach a process running in background:
tmux ls
tmux attach -t insolard

# To copy a file from `jepsen-1` pod:
scp -o 'StrictHostKeyChecking no' -i ./base-image/id\_rsa -P 32001 gopher@localhost:.bash_profile ./

# Aggregate all logfiles:
./aggregate-logs.py /tmp/jepsen-agg/

# Example of how to sort and properly format logs for a given trace id:
gunzip /tmp/jepsen-agg/320*/*.log.gz
grep -r 32bc366d-b144-4765-9483-6be37c55fd9d ./320* > trace.txt
cat trace.txt | ./format-trace-logs.py | \
  grep -v '"caller":"insolar/bus/bus' | \
  grep -v '"caller":"network/' | sort > trace-sorted.txt
```
