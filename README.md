# insolar-jepsen

Jepsen-like tests for Insolar.

**Requirements:** docker, kubectl, jq, python3.

If you are using Docker Desktop, please note, that by default it uses rather strict resource limits. You might want to change these limits in Preferences... -> Advanced tab.

## Usage

```
# Make sure private key is readable only by current user
chmod 600 ./base-image/id_rsa

# Label current node: jepsen=true
kubectl label node docker-desktop jepsen=true

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
ssh -o 'StrictHostKeyChecking no' -i ./base-image/id_rsa -p 32001 gopher@localhost

# To attach a process running in background:
tmux ls
tmux attach -t insolard

# To copy a file from `jepsen-1` pod:
scp -o 'StrictHostKeyChecking no' -i ./base-image/id_rsa -P 32001 gopher@localhost:.bash_profile ./

# Aggregate all logfiles:
./aggregate-logs.py /tmp/jepsen-agg/

# Example of how to sort and properly format logs for a given trace id:
gunzip /tmp/jepsen-agg/320*/*.log.gz
grep -r 32bc366d-b144-4765-9483-6be37c55fd9d ./320* > trace.txt
cat trace.txt | ./format-trace-logs.py | \
  grep -v '"caller":"insolar/bus/bus' | \
  grep -v '"caller":"network/' | sort > trace-sorted.txt
```

## How to run go-autotests

The projects mentioned in this sections are closed-source for now, sorry.

`--other-path` should contain the following repos:

* observer
* wallet-api-insolar-balance
* wallet-api-insolar-transactions
* migration-address-api
* wallet-api-insolar-price
* xns-coin-stats

All but observer should be compiled using `gradle bootJar`.

```
./run-test.py --debug -i insolar-jepsen:latest --others-path .. --skip-all-tests

# test the API endpoint:
curl -vvv http://localhost:31009/api/rpc

# collect keys and configs required for go-autotests:
rm -r /tmp/jepsen-keys || true
mkdir /tmp/jepsen-keys
scp -o 'StrictHostKeyChecking no' -i ./base-image/id_rsa -P32001 -r 'gopher@localhost:go/src/github.com/insolar/insolar/scripts/insolard/configs/migration_*_member_keys.json' /tmp/jepsen-keys/
scp -o 'StrictHostKeyChecking no' -i ./base-image/id_rsa -P32001 -r gopher@localhost:go/src/github.com/insolar/insolar/scripts/insolard/bootstrap.yaml /tmp/jepsen-keys/

# run go-autotests
IS_LOCAL_RUN=0 IS_JEPSEN_RUN=1 go test -tags 'platform manual observer_api' ./...
# instead of using environment variables you can edit apitests/entrypoint.yaml:
# is_local_run: false, is_jepsen_run: true
```
