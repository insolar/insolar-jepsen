FROM ubuntu:16.04

RUN apt-get update && apt-get install -y openssh-server iptables net-tools iputils-ping vim sudo
RUN mkdir /var/run/sshd
RUN adduser --disabled-password --gecos '' gopher
RUN usermod -a -G sudo gopher
RUN sed -i 's/ALL=(ALL:ALL) ALL/ALL=(ALL:ALL) NOPASSWD:ALL/' /etc/sudoers
RUN mkdir /home/gopher/.ssh
# see ./ssh-keys/id_rsa.pub
RUN echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCrSwFcURYecjrYzqPRZrAl14v8fzfAlB5CDqNBSFQr8DKJzLAXA3Eqk5BFPIziE+UUHARufbaefuW+Vbk4bsUJurimgE62z4oh71KddTMyQUhF/MkO0FARWX5tNVaVxCkI1/2ni7uVd7uHMn4mMJh2P+9STwvlPTaCfRbwaihvoxlqY6jiQ6zgvG4U0Ov2aqqNbrDQ45dTqMtFsaEjQG+TgxDuC4VMNLyfSezV5JQWNqJr0m56yJib6G74cLrwe5+NYbrlNMLsd2GdrH4g8Qkl4LYDRVAQRhQKPSqrZ6QULluKVpmh6YjOZaPilc7j7zreAo8KyTV4P47g8vym28VV eax@Aleksanders-MacBook-Pro.local' > /home/gopher/.ssh/authorized_keys

# Just in case:
RUN echo 'root:root' | chpasswd
RUN sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# SSH login fix. Otherwise user is kicked off after login
RUN sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd

ENV NOTVISIBLE "in users profile"
RUN echo "export VISIBLE=now" >> /etc/profile

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
