# Copyright (c) 2016 Alexander Lamaison <alexander.lamaison@gmail.com>
#
# Redistribution and use in source and binary forms,
# with or without modification, are permitted provided
# that the following conditions are met:
#
#   Redistributions of source code must retain the above
#   copyright notice, this list of conditions and the
#   following disclaimer.
#
#   Redistributions in binary form must reproduce the above
#   copyright notice, this list of conditions and the following
#   disclaimer in the documentation and/or other materials
#   provided with the distribution.
#
#   Neither the name of the copyright holder nor the names
#   of any other contributors may be used to endorse or
#   promote products derived from this software without
#   specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
# CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
# OF SUCH DAMAGE.

FROM debian:jessie

RUN apt-get update \
 && apt-get install -y openssh-server \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*
RUN mkdir /var/run/sshd

# Chmodding because, when building on Windows, files are copied in with
# -rwxr-xr-x permissions.
#
# Copying to a temp location, then moving because chmodding the copied file has
# no effect (Docker AUFS-related bug maybe?)
COPY ssh_host_rsa_key /tmp/etc/ssh/ssh_host_rsa_key
RUN mv /tmp/etc/ssh/ssh_host_rsa_key /etc/ssh/ssh_host_rsa_key
RUN chmod 600 /etc/ssh/ssh_host_rsa_key

RUN adduser --disabled-password --gecos 'Test user for libssh2 integration tests' libssh2
RUN echo 'libssh2:my test password' | chpasswd

RUN sed -i 's/ChallengeResponseAuthentication no/ChallengeResponseAuthentication yes/' /etc/ssh/sshd_config

# SSH login fix. Otherwise user is kicked off after login
RUN sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd

USER libssh2

RUN mkdir -p /home/libssh2/.ssh
RUN mkdir -p /home/libssh2/sandbox

COPY authorized_keys /tmp/libssh2/.ssh/authorized_keys
RUN cp /tmp/libssh2/.ssh/authorized_keys /home/libssh2/.ssh/authorized_keys
RUN chmod 600 /home/libssh2/.ssh/authorized_keys

USER root

EXPOSE 22
# -e gives logs via 'docker logs'
CMD ["/usr/sbin/sshd", "-D", "-e"]
