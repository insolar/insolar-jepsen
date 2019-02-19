# insolar-jepsen

Jepsen-like tests for Insolar.

Usage:

```
docker build -t insolar-jepsen .
# test the image, it should not throw any errors:
# docker run --rm -it insolar-jepsen

# ./gen-jepsen-pods.py > ./jepsen-pods.yml
kubectl apply -f jepsen-pods.yml

# To login to `jepsen-1` pod:
# ssh -o 'StrictHostKeyChecking no' -i ./ssh-keys/id_rsa -p 32001 gopher@localhost
```
