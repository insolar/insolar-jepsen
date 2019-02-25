# insolar-jepsen

Jepsen-like tests for Insolar.

Requirements: docker, kubectl, jq. If you are using Docker Desktop, please note, that by default it uses rather strict resource limits. You might want to change these limits in Preferences... -> Advanced tab.

Usage:

```
# the complete build takes ~10 minutes
docker build --no-cache -t insolar-jepsen --build-arg BRANCH=master .

# test the image, it should throw no errors:
# docker run --rm -it insolar-jepsen

# Optional:
# ./gen-jepsen-pods.py > ./jepsen-pods.yml

# Make sure private key is readable only by current user
chmod 600 ./ssh-keys/id_rsa

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
