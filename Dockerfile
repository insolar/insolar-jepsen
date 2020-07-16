# vim: set ai et ts=4 sw=4:

FROM tsovak/insolar-jepsen-base

ARG CACHE=1
ARG BRANCH
ENV BRANCH ${BRANCH:-master}
RUN git config --global user.name 'Kyle Kingsbury'
RUN git config --global user.email 'jepsen@insolar.io'
RUN git remote prune origin && git pull
# Remove untracked files, e.g. go.mod
RUN git clean -f 
RUN git checkout .
RUN git checkout $BRANCH
RUN git merge origin/master --no-edit
RUN make install-deps && \
  (make ensure || rm -rvf vendor && make ensure) && \
  make all
RUN mkdir -p scripts/insolard/configs
RUN mkdir -p scripts/insolard/certs
RUN ./bin/insolar gen-key-pair --target=node > scripts/insolard/configs/pulsar_keys.json
RUN ./bin/insolar gen-key-pair --target=user > scripts/insolard/configs/root_member_keys.json
RUN ./bin/insolar gen-key-pair --target=user > scripts/insolard/configs/fee_member_keys.json
RUN ./bin/insolar gen-key-pair --target=user > scripts/insolard/configs/migration_admin_member_keys.json
RUN ./bin/insolar gen-key-pair --target=user > scripts/insolard/configs/funds_and_enterprise_member_keys.json
RUN for m in $(seq 0 9); do ./bin/insolar gen-key-pair --target=node > \
  scripts/insolard/configs/migration_daemon_${m}_member_keys.json; done
RUN for m in $(seq 0 19); do ./bin/insolar gen-key-pair --target=user > \
  scripts/insolard/configs/network_incentives_${m}_member_keys.json; done
RUN for m in $(seq 0 19); do ./bin/insolar gen-key-pair --target=user > \
  scripts/insolard/configs/application_incentives_${m}_member_keys.json; done
RUN for m in $(seq 0 19); do ./bin/insolar gen-key-pair --target=user > \
  scripts/insolard/configs/foundation_${m}_member_keys.json; done
RUN ./bin/insolar gen-key-pair --target=user > scripts/insolard/configs/enterprise_0_member_keys.json

RUN ./bin/insolar gen-migration-addresses > scripts/insolard/configs/migration_addresses.json || true

RUN cd scripts/insolard/configs && ls && cd ../../..

COPY config-templates/bootstrap.yaml ./scripts/insolard/bootstrap.yaml
RUN mkdir -p scripts/insolard/reusekeys/not_discovery
RUN mkdir -p scripts/insolard/reusekeys/discovery

RUN curl -sL https://github.com/fullstorydev/grpcurl/releases/download/v1.6.1/grpcurl_1.6.1_linux_x86_64.tar.gz | tar xzf - && mv grpcurl /home/gopher/go/bin/grpcurl | rm *.tar.gz
RUN go get github.com/insolar/insolar/cmd/backupmanager

EXPOSE 22
CMD ["/usr/bin/sudo", "/usr/sbin/sshd", "-D"]
