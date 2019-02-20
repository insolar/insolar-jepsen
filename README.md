# insolar-jepsen

Jepsen-like tests for Insolar.

Requirements: docker, kubectl, jq.

Usage:

```
# the complete build takes ~10 minutes
docker build --no-cache -t insolar-jepsen .

# this method is faster when rebuilding, but sometimes doesn't work well
# docker build --build-arg DISABLE_CACHE_HERE=$(date +%s) -t insolar-jepsen .

# test the image, it should throw no errors:
# docker run --rm -it insolar-jepsen

# Optional:
# ./gen-jepsen-pods.py > ./jepsen-pods.yml

./run-test
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
