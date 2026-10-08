FROM alpine:3.22
RUN apk add --no-cache openssl
COPY deploy/docker/test-ca.sh /usr/local/bin/test-ca
ENTRYPOINT ["/bin/sh", "/usr/local/bin/test-ca"]
