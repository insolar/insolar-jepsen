# vim: set ai et ts=4 sw=4:

FROM tsovak/insolar-jepsen-base

ARG CACHE=1
ARG BRANCH
ENV BRANCH ${BRANCH:-master}
RUN git pull
RUN git checkout $BRANCH
RUN rm -rf ./.dockerignore
RUN make install-deps ensure
RUN make clean build
RUN mkdir -p scripts/insolard/configs || true
RUN mkdir -p scripts/insolard/discoverynodes/certs || true
RUN ./bin/insolar gen-key-pair > scripts/insolard/configs/bootstrap_keys.json
RUN ./bin/insolar gen-key-pair > scripts/insolard/configs/root_member_keys.json
COPY config-templates/genesis.yaml ./scripts/insolard/genesis.yaml
COPY config-templates/insolar_genesis.yaml ./scripts/insolard/insolar.yaml
RUN ./bin/insolard --config scripts/insolard/insolar.yaml \
        --genesis scripts/insolard/genesis.yaml \
        --keyout scripts/insolard/discoverynodes/certs

EXPOSE 22
CMD ["/usr/bin/sudo", "/usr/sbin/sshd", "-D"]
