FROM ubuntu:16.04

RUN apt-get update && apt-get install -y openssh-server iptables net-tools iputils-ping vim sudo git make lsof gcc curl tmux
RUN mkdir /var/run/sshd
RUN adduser --disabled-password --gecos '' gopher
RUN usermod -a -G sudo gopher
RUN sed -i 's/ALL=(ALL:ALL) ALL/ALL=(ALL:ALL) NOPASSWD:ALL/' /etc/sudoers

# Just in case:
RUN echo 'root:root' | chpasswd
RUN sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# SSH login fix. Otherwise user is kicked off after login
RUN sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd

ENV NOTVISIBLE "in users profile"
RUN echo "export VISIBLE=now" >> /etc/profile

USER gopher
ENV PATH="/home/gopher/go/bin:/home/gopher/opt/go/bin:${PATH}"

RUN mkdir /home/gopher/.ssh
# see ./ssh-keys/id_rsa.pub
RUN echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCrSwFcURYecjrYzqPRZrAl14v8fzfAlB5CDqNBSFQr8DKJzLAXA3Eqk5BFPIziE+UUHARufbaefuW+Vbk4bsUJurimgE62z4oh71KddTMyQUhF/MkO0FARWX5tNVaVxCkI1/2ni7uVd7uHMn4mMJh2P+9STwvlPTaCfRbwaihvoxlqY6jiQ6zgvG4U0Ov2aqqNbrDQ45dTqMtFsaEjQG+TgxDuC4VMNLyfSezV5JQWNqJr0m56yJib6G74cLrwe5+NYbrlNMLsd2GdrH4g8Qkl4LYDRVAQRhQKPSqrZ6QULluKVpmh6YjOZaPilc7j7zreAo8KyTV4P47g8vym28VV eax@Aleksanders-MacBook-Pro.local' > /home/gopher/.ssh/authorized_keys

RUN bash -c 'cd /home/gopher && wget https://dl.google.com/go/go1.11.5.linux-amd64.tar.gz && tar -xvzf *.tar.gz && rm *.tar.gz && rm -r gocache && rm -r tmp && mkdir opt && mv go opt/go && mkdir -p go/bin && echo "export PATH=\"/home/gopher/go/bin:/home/gopher/opt/go/bin:\$PATH\"" > /home/gopher/.bash_profile'
RUN bash -c 'cd /home/gopher && curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh'

RUN bash -c 'cd /home/gopher && mkdir -p go/src/github.com/insolar && cd go/src/github.com/insolar && git clone https://github.com/insolar/insolar.git && cd insolar && make install-deps pre-build && make clean build'

# To build Insolar only two steps left: git pull (to update the source code) + make clean build
# Also cached binaries available if necessary

EXPOSE 22
CMD ["/usr/bin/sudo", "/usr/sbin/sshd", "-D"]
