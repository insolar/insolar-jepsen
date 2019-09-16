# vim: set ai et ts=4 sw=4:
FROM golang:1.12.9 AS gotools
RUN go get github.com/fullstorydev/grpcurl && go install github.com/fullstorydev/grpcurl/cmd/grpcurl

FROM ubuntu:16.04

# STEP 1: Base image dependencies
RUN apt-get update && apt-get install -y \
 openssh-server iptables net-tools \
 iputils-ping vim sudo git make lsof gcc curl tmux psmisc \
 timelimit tree && apt-get clean

RUN mkdir /var/run/sshd
RUN adduser --disabled-password --gecos '' gopher
RUN usermod -a -G sudo gopher
RUN sed -i 's/ALL=(ALL:ALL) ALL/ALL=(ALL:ALL) NOPASSWD:ALL/' \
    /etc/sudoers

# Just in case:
RUN echo 'root:root' | chpasswd
RUN sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' \
    /etc/ssh/sshd_config

# SSH login fix. Otherwise user is kicked off after login
RUN sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' \
    -i /etc/pam.d/sshd

ENV NOTVISIBLE "in users profile"
RUN echo "export VISIBLE=now" >> /etc/profile

USER gopher
WORKDIR /home/gopher
ENV PATH="/home/gopher/bin:${PATH}"
RUN echo "export PATH=\"/home/gopher/bin:\$PATH\"" > /home/gopher/.bash_profile
RUN mkdir .ssh
COPY base-image/id_rsa.pub ./.ssh/authorized_keys
# make sure file has the right permissions, dirty workaround for Docker
RUN sudo chown gopher:gopher ./.ssh/authorized_keys

# STEP 2: Prepare files for Jepsen tests
COPY --chown=gopher --from=insolar-base \
  "/go/src/github.com/insolar/insolar/bin/" "/home/gopher/bin"

# Configure insolar
RUN mkdir -p node-configs \
    mkdir -p scripts/insolard/configs && \
    mkdir -p scripts/insolard/certs

RUN ./bin/insolar gen-key-pair > scripts/insolard/configs/pulsar_keys.json && \
    ./bin/insolar gen-key-pair > scripts/insolard/configs/root_member_keys.json && \
    ./bin/insolar gen-key-pair > scripts/insolard/configs/fee_member_keys.json && \
    ./bin/insolar gen-key-pair > scripts/insolard/configs/funds_and_enterprise_member_keys.json && \
    ./bin/insolar gen-key-pair > scripts/insolard/configs/migration_admin_member_keys.json

RUN for m in $(seq 0 9); do ./bin/insolar gen-key-pair > \
  scripts/insolard/configs/migration_daemon_${m}_member_keys.json; done
RUN for m in $(seq 0 39); do ./bin/insolar gen-key-pair > \
  scripts/insolard/configs/network_incentives_${m}_member_keys.json; done
RUN for m in $(seq 0 39); do ./bin/insolar gen-key-pair > \
  scripts/insolard/configs/application_incentives_${m}_member_keys.json; done
RUN for m in $(seq 0 13); do ./bin/insolar gen-key-pair > \
  scripts/insolard/configs/foundation_${m}_member_keys.json; done

RUN ./bin/insolar gen-migration-addresses > scripts/insolard/configs/migration_addresses.json || true

RUN cd scripts/insolard/configs && ls && cd ../../..

COPY config-templates/bootstrap.yaml ./scripts/insolard/bootstrap.yaml
RUN ./bin/insolar bootstrap --config scripts/insolard/bootstrap.yaml \
  --certificates-out-dir scripts/insolard/certs

# grpcurl stuff
COPY --chown=gopher --from=gotools "/go/bin/grpcurl" "/home/gopher/bin/grpcurl"
COPY --chown=gopher --from=insolar-base \
    "/go/src/github.com/insolar/insolar/vendor/github.com/gogo/protobuf/" \
                          "/home/gopher/go/src/github.com/gogo/protobuf"
# add proto files for grpcurl
COPY --chown=gopher --from=insolar-base \
                "/go/src/github.com/insolar/insolar/insolar/" \
    "/home/gopher/go/src/github.com/insolar/insolar/insolar/"
COPY --chown=gopher --from=insolar-base \
                "/go/src/github.com/insolar/insolar/ledger/heavy/exporter/" \
    "/home/gopher/go/src/github.com/insolar/insolar/ledger/heavy/exporter/"

EXPOSE 22
CMD ["/usr/bin/sudo", "/usr/sbin/sshd", "-D"]
