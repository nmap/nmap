FROM debian
RUN apt update && apt install make gcc git g++ -y
RUN git clone 'https://github.com/nmap/nmap.git'
# Install dependencies

RUN apk add --update --no-cache \
            ca-certificates \
            libpcap \
            libgcc libstdc++ \
            libssl3 \
 && update-ca-certificates \
 && rm -rf /var/cache/apk/*


# Compile and install Nmap from sources
RUN apk add --update --no-cache --virtual .build-deps \
        libpcap-dev lua-dev linux-headers openssl-dev \
        autoconf g++ libtool make \
        curl
WORKDIR nmap
RUN pwd
RUN ./configure
RUN make
RUN make install
ENTRYPOINT ["/usr/local/bin/nmap"]
