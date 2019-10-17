# vim: set ai et ts=4 sw=4:

FROM ubuntu:16.04

MAINTAINER Tsovak Sahakyan 

# wget is required to add PPA
RUN apt-get update
RUN apt-get install -y wget

# Observer depends on PostgreSQL 11+
RUN echo 'deb http://apt.postgresql.org/pub/repos/apt/ xenial-pgdg main' > /etc/apt/sources.list.d/pgdg.list
RUN wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | apt-key add -

RUN apt-get update
RUN apt-get install -y openssh-server iptables net-tools \
    iputils-ping vim sudo git make lsof gcc curl tmux psmisc \
    timelimit tree htop telnet
RUN apt-get clean

# Speeds up Observer deployment
RUN apt-get install -y --download-only postgresql-11

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
COPY id_rsa.pub ./.ssh/authorized_keys
# make sure file has the right permissions, dirty workaround for Docker
RUN sudo chown gopher:gopher ./.ssh/authorized_keys
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
RUN make install-deps ensure

