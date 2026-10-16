FROM alpine:3.21

RUN apk add --no-cache tor && \
    mkdir -p /var/lib/tor && \
    chown -R tor:nogroup /var/lib/tor && \
    chmod 700 /var/lib/tor

COPY torrc /etc/tor/torrc

USER tor
EXPOSE 9050
CMD ["tor", "-f", "/etc/tor/torrc"]
