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
RUN ./bin/insolar gen-key-pair > scripts/insolard/configs/bootstrap_keys.json
RUN ./bin/insolar gen-key-pair > scripts/insolard/configs/root_member_keys.json
COPY config-templates/bootstrap.yaml ./scripts/insolard/bootstrap.yaml
RUN ./bin/insolar bootstrap --config scripts/insolard/bootstrap.yaml \
  --certificates-out-dir scripts/insolard/discoverynodes/certs

EXPOSE 22
CMD ["/usr/bin/sudo", "/usr/sbin/sshd", "-D"]
