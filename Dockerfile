FROM alt:latest

RUN apt-get update
RUN apt-get install -y openssh-server

RUN ssh-keygen -A

RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/openssh/sshd_config && \
  sed -i 's/#PubkeyAuthentication/PubkeyAuthentication/' /etc/openssh/sshd_config && \
  printf 'AuthorizedKeysFile %s\n' /root/.ssh/authorized_keys >> /etc/openssh/sshd_config

CMD ["/usr/sbin/sshd", "-D"]
