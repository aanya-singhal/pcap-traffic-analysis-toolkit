# Attacker / client tooling image: tiny Alpine with nmap + curl.
FROM alpine:3.20
RUN apk add --no-cache nmap curl
COPY docker/attacker.sh /attacker.sh
COPY docker/client.sh /client.sh
RUN chmod +x /attacker.sh /client.sh
CMD ["/bin/sh"]
