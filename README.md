# insolar-jepsen

Jepsen-like tests for Insolar.

Usage:

```
docker build -t ubuntu-ssh .
# ./gen-jepsen-pods.py > ./jepsen-pods.yml
kubectl create -f jepsen-pods.yml
```
