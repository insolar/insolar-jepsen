# insolar-jepsen

Jepsen-like tests for Insolar.

**Requirements:** docker, kubectl, jq, python3.

If you are using Docker Desktop, please note, that by default it uses rather strict resource limits. You might want to change these limits in Preferences... -> Advanced tab.

## Usage: common part

```
# Make sure private key is readable only by current user
chmod 600 ./base-image/id_rsa

# to build the base image:
cd base-image && docker build --no-cache -t tsovak/insolar-jepsen-base . && cd ..

# to build the image of Insolar Platform from the given branch:
./build-docker.py branch-name
```

## Usage: how to run Jepsen-tests

```
# use --help flag to see all arguments
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

## Usage: how to run go-autotests

The projects mentioned in this sections are closed-source for now, sorry.

`--other-path` should contain the following repos:

* observer

```
# skipped: steps from "Usage" section above
./run-test.py --debug -i insolar-jepsen:latest --others-path .. --skip-all-tests

# test the API endpoint:
curl -vvv -XPOST http://localhost:31009/api/rpc

# collect keys and configs required for go-autotests:
rm -r /tmp/jepsen-keys || true
mkdir /tmp/jepsen-keys
scp -o 'StrictHostKeyChecking no' -i ./base-image/id_rsa -P32001 -r 'gopher@localhost:go/src/github.com/insolar/insolar/scripts/insolard/configs/migration_*_member_keys.json' /tmp/jepsen-keys/
scp -o 'StrictHostKeyChecking no' -i ./base-image/id_rsa -P32001 -r gopher@localhost:go/src/github.com/insolar/insolar/scripts/insolard/bootstrap.yaml /tmp/jepsen-keys/bootstrap_default.yaml

# run go-autotests
IS_LOCAL_RUN=0 IS_JEPSEN_RUN=1 go test --count=1 -tags 'platform observer_api' ./...
# instead of using environment variables you can edit apitests/entrypoint.yaml:
# is_local_run: false, is_jepsen_run: true
```

## Re-deploy observer only

```
# Re-deploy observer, keeping the database
./run-test.py --debug -i insolar-jepsen:latest --others-path .. --skip-all-tests --redeploy-observer --keep-database true

# Re-deploy observer, purging the database
./run-test.py --debug -i insolar-jepsen:latest --others-path .. --skip-all-tests --redeploy-observer --keep-database false
```
