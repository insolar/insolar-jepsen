# insolar-jepsen

Jepsen-like tests for Insolar.

Requirements: docker, kubectl, jq.

Usage:

```
docker build -t insolar-jepsen .
# test the image, it should throw no errors:
# docker run --rm -it insolar-jepsen

# Optional:
# ./gen-jepsen-pods.py > ./jepsen-pods.yml

./run-test --skip-build
```

Adter the test:

```
# To login to `jepsen-1` pod:
ssh -o 'StrictHostKeyChecking no' -i ./ssh-keys/id_rsa -p 32001 gopher@localhost

# To attach a process running in background in tmux:
tmux ls
tmux attach -t insolard

# To copy a file from `jepsen-1` pod:
scp -o 'StrictHostKeyChecking no' -i ./ssh-keys/id_rsa -P 32001 gopher@localhost:.bash_profile ./
```
