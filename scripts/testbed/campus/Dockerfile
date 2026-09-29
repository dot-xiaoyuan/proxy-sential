FROM alpine:3.21
RUN apk add --no-cache tcpdump suricata python3 openssl iproute2 iptables
COPY campus-load /usr/local/bin/campus-load
WORKDIR /results
ENTRYPOINT ["/bin/sh"]
