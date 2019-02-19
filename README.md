# insolar-jepsen

Jepsen-like tests for Insolar.

Usage:

```
docker build -t ubuntu-ssh .
kubectl create -f insolar-jepsen.yml
kubectl expose deployment insolar-jepsen
kubectl get pods -l app=insolar-jepsen -o wide
```
