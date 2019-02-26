# insolar-jepsen

Jepsen-like tests for Insolar.

Requirements: docker, kubectl, jq. If you are using Docker Desktop, please note, that by default it uses rather strict resource limits. You might want to change these limits in Preferences... -> Advanced tab.

Usage:

```
# Make sure private key is readable only by current user
chmod 600 ./ssh-keys/id_rsa

# first build takes 11 min, second build - 2 min 40 sec
./build-docker.py branch-name

# run tests
./run-test.py
```

After the test:

```
# To login to `jepsen-1` pod:
ssh -o 'StrictHostKeyChecking no' -i ./ssh-keys/id_rsa -p 32001 gopher@localhost

# To attach a process running in background:
tmux ls
tmux attach -t insolard

# To copy a file from `jepsen-1` pod:
scp -o 'StrictHostKeyChecking no' -i ./ssh-keys/id_rsa -P 32001 gopher@localhost:.bash_profile ./
```
