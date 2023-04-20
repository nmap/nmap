FROM debian
RUN apt update && apt install python3 make gcc git g++ wget build-essential libpcre3-dev libssl-dev libpcap-dev openssl -y
RUN git clone 'https://github.com/nmap/nmap.git'
WORKDIR nmap
RUN ./configure
RUN make
RUN make install
ENTRYPOINT ["/usr/local/bin/nmap"]
