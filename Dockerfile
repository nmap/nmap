FROM gcc:8.2.0 as TEMP

ENV CFLAGS="-march=core2 -O2 -fomit-frame-pointer -pipe -fPIC"
ENV CXXFLAGS="-march=core2 -O2 -fomit-frame-pointer -pipe -fPIC"

COPY . /app
WORKDIR /app

RUN ./configure --without-subversion --without-liblua --without-zenmap \
  --with-pcre=/usr --with-libpcap=included --with-libdnet=included --without-ndiff \
  --without-nmap-update --without-ncat --without-liblua --without-nping \
  --without-openssl 
RUN make

FROM ubuntu:18.04
COPY --from=TEMP /app/nmap /nmap
CMD [ "/nmap" ]
