# insolar-jepsen

Jepsen-like tests for Insolar.

Requirements: docker, kubectl, jq. If you are using Docker Desktop, please note, that by default it uses rather strict resource limits. You might want to change these limits in Preferences... -> Advanced tab.

Usage:

```
# Make sure private key is readable only by current user
chmod 600 ./base-image/id_rsa

# Label current node: jepsen=true
kubectl label node docker-for-desktop jepsen=true

# to build the base image as well:
# cd base-image && docker build -t tsovak/insolar-jepsen-base .
./build-docker.py branch-name

# run tests (use --help flag to see all arguments)
./run-test.py -i insolar-jepsen:latest
```

After the test:

```
# To login to `jepsen-1` pod:
ssh -o 'StrictHostKeyChecking no' -i ./base-image/id_rsa -p 32001 gopher@localhost

# To attach a process running in background:
tmux ls
tmux attach -t insolard

# To copy a file from `jepsen-1` pod:
scp -o 'StrictHostKeyChecking no' -i ./base-image/id_rsa -P 32001 gopher@localhost:.bash_profile ./
```
