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
# To copy a file from `jepsen-1` pod:
# scp -o 'StrictHostKeyChecking no' -i ./ssh-keys/id_rsa -P 32001 gopher@localhost:.bash_profile ./
```

```
# ssh -o 'StrictHostKeyChecking no' -i ./ssh-keys/id_rsa -p 32001 gopher@localhost "bash -c 'source ./.bash_profile ; cd go/src/github.com/insolar/insolar && make clean build && bin/insolar -c gen_keys > scripts/insolard/configs/bootstrap_keys.json && bin/insolar -c gen_keys > scripts/insolard/configs/root_member_keys.json && go run scripts/generate_insolar_configs.go -o scripts/insolard/configs/generated_configs -p scripts/insolard/configs/insgorund_ports.txt -g scripts/insolard/genesis.yaml -t scripts/insolard/pulsar_template.yaml && bin/insolard --config scripts/insolard/insolar.yaml --genesis scripts/insolard/genesis.yaml --keyout scripts/insolard/discoverynodes/certs'"

ssh -o 'StrictHostKeyChecking no' -i ./ssh-keys/id_rsa -p 32001 gopher@localhost "bash -c 'source ./.bash_profile ; cd go/src/github.com/insolar/insolar && make clean build"

scp -r -o 'StrictHostKeyChecking no' -i ./ssh-keys/id_rsa -P 32001 gopher@localhost:go/src/github.com/insolar/insolar/data /tmp/insolar-jepsen-data
```
