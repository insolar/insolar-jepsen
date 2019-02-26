# vim: set ai et ts=4 sw=4:

FROM ubuntu:16.04

RUN apt-get update
RUN apt-get install -y openssh-server iptables net-tools \
    iputils-ping vim sudo git make lsof gcc curl tmux psmisc
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
ENV PATH="/home/gopher/go/bin:/home/gopher/opt/go/bin:${PATH}"
RUN mkdir .ssh
COPY ssh-keys/id_rsa.pub ./.ssh/authorized_keys
RUN wget https://dl.google.com/go/go1.12.linux-amd64.tar.gz
RUN tar -xvzf *.tar.gz
RUN rm *.tar.gz
RUN rm -r gocache || true
RUN rm -r tmp || true
RUN mkdir opt
RUN mv go opt/go
RUN mkdir -p go/bin
RUN echo "export PATH=\"/home/gopher/go/bin:/home/gopher/opt/go/bin:\$PATH\"" > \
    /home/gopher/.bash_profile
RUN curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh
RUN mkdir -p go/src/github.com/insolar

WORKDIR /home/gopher/go/src/github.com/insolar
RUN git clone https://github.com/insolar/insolar.git

WORKDIR /home/gopher/go/src/github.com/insolar/insolar
RUN make install-deps pre-build
ARG CACHE=1
ARG BRANCH
ENV BRANCH ${BRANCH:-master}
RUN git pull
RUN git checkout $BRANCH
RUN make install-deps pre-build
COPY config-templates/genesis.yaml ./scripts/insolard/genesis.yaml
COPY config-templates/pulsar_template.yaml ./scripts/insolard/pulsar_template.yaml
RUN make clean build
RUN ./bin/insolar -c gen_keys > scripts/insolard/configs/bootstrap_keys.json
RUN ./bin/insolar -c gen_keys > scripts/insolard/configs/root_member_keys.json
RUN go run scripts/generate_insolar_configs.go \
        -o scripts/insolard/configs/generated_configs \
        -p scripts/insolard/configs/insgorund_ports.txt \
        -g scripts/insolard/genesis.yaml \
        -t scripts/insolard/pulsar_template.yaml
RUN ./bin/insolard --config scripts/insolard/insolar.yaml \
        --genesis scripts/insolard/genesis.yaml \
        --keyout scripts/insolard/discoverynodes/certs

EXPOSE 22
CMD ["/usr/bin/sudo", "/usr/sbin/sshd", "-D"]
