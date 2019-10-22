# vim: set ai et ts=4 sw=4:

FROM tsovak/insolar-jepsen-base

ARG CACHE=1
ARG BRANCH
ENV BRANCH ${BRANCH:-master}
RUN git config --global user.name 'Kyle Kingsbury'
RUN git config --global user.email 'jepsen@insolar.io'
RUN git remote prune origin && git pull
RUN git checkout $BRANCH
RUN git merge origin/master --no-edit
# Dirty hack: clone submodules using HTTPS instead of SSH, since Github requires
# registration to use SSH. This will most likely go away after introduction of contract compiler.
RUN perl -i.back -pe 's!\bgit\@github.com:!https://github.com/!' .gitmodules
RUN make submodule || true
RUN make install-deps && \
  (make ensure || rm -rvf vendor && make ensure) && \
  make clean && \
  make build
RUN mkdir -p scripts/insolard/configs
RUN mkdir -p scripts/insolard/certs
RUN ./bin/insolar gen-key-pair > scripts/insolard/configs/pulsar_keys.json
RUN ./bin/insolar gen-key-pair > scripts/insolard/configs/root_member_keys.json
RUN ./bin/insolar gen-key-pair > scripts/insolard/configs/fee_member_keys.json
RUN ./bin/insolar gen-key-pair > scripts/insolard/configs/migration_admin_member_keys.json
RUN ./bin/insolar gen-key-pair > scripts/insolard/configs/funds_and_enterprise_member_keys.json
RUN for m in $(seq 0 9); do ./bin/insolar gen-key-pair > \
  scripts/insolard/configs/migration_daemon_${m}_member_keys.json; done
RUN for m in $(seq 0 39); do ./bin/insolar gen-key-pair > \
  scripts/insolard/configs/network_incentives_${m}_member_keys.json; done
RUN for m in $(seq 0 39); do ./bin/insolar gen-key-pair > \
  scripts/insolard/configs/application_incentives_${m}_member_keys.json; done
RUN for m in $(seq 0 39); do ./bin/insolar gen-key-pair > \
  scripts/insolard/configs/foundation_${m}_member_keys.json; done
RUN for m in $(seq 0 1); do ./bin/insolar gen-key-pair > \
    scripts/insolard/configs/funds_${m}_member_keys.json; done
RUN for m in $(seq 0 3); do ./bin/insolar gen-key-pair > \
    scripts/insolard/configs/enterprise_${m}_member_keys.json; done

RUN ./bin/insolar gen-migration-addresses > scripts/insolard/configs/migration_addresses.json || true

RUN cd scripts/insolard/configs && ls && cd ../../..

COPY config-templates/bootstrap.yaml ./scripts/insolard/bootstrap.yaml
RUN ./bin/insolar bootstrap --config scripts/insolard/bootstrap.yaml \
  --certificates-out-dir scripts/insolard/certs

RUN go get github.com/fullstorydev/grpcurl
RUN go install github.com/fullstorydev/grpcurl/cmd/grpcurl

EXPOSE 22
CMD ["/usr/bin/sudo", "/usr/sbin/sshd", "-D"]
