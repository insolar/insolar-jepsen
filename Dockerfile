# vim: set ai et ts=4 sw=4:

FROM tsovak/insolar-jepsen-base

ARG CACHE=1
ARG BRANCH
ENV BRANCH ${BRANCH:-master}
RUN git remote prune origin && git pull
RUN git checkout $BRANCH
RUN make install-deps && \
  (make ensure || rm -rvf vendor && make ensure) && \
  make clean && \
  make build
RUN mkdir -p scripts/insolard/configs
RUN mkdir -p scripts/insolard/discoverynodes/certs
RUN ./bin/insolar gen-key-pair > scripts/insolard/configs/pulsar_keys.json
RUN ./bin/insolar gen-key-pair > scripts/insolard/configs/root_member_keys.json
RUN ./bin/insolar gen-key-pair > scripts/insolard/configs/migration_admin_member_keys.json
RUN for m in $(seq 0 9); do ./bin/insolar gen-key-pair > \
  scripts/insolard/configs/migration_daemon_${m}_member_keys.json; done
RUN ./bin/insolar gen-migration-addresses > scripts/insolard/configs/migration_addresses.json || true

RUN cd scripts/insolard/configs && ls && cd ../../..

COPY config-templates/bootstrap.yaml ./scripts/insolard/bootstrap.yaml
RUN ./bin/insolar bootstrap --config scripts/insolard/bootstrap.yaml \
  --certificates-out-dir scripts/insolard/discoverynodes/certs

EXPOSE 22
CMD ["/usr/bin/sudo", "/usr/sbin/sshd", "-D"]
