FROM debian
RUN apt update && apt install make gcc git g++ -y
RUN git clone 'https://github.com/nmap/nmap.git'
WORKDIR nmap
RUN ./configure
RUN make
RUN make install
ENTRYPOINT ["/usr/local/bin/nmap"]
