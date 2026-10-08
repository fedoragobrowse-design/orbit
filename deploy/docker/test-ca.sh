#!/bin/sh
set -eu
umask 077
if [ ! -s /ca/ca.key ]; then
  openssl req -x509 -newkey rsa:3072 -nodes -days 7 -sha256 -keyout /ca/ca.key -out /ca/ca.crt -subj '/CN=Orbit disposable test CA'
fi
issue() {
  name="$1"; target="$2"
  openssl req -new -newkey rsa:2048 -nodes -keyout "$target/$name.key" -out "/ca/$name.csr" -subj "/CN=$name"
  printf 'subjectAltName=DNS:%s,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature,keyEncipherment\n' "$name" > "/ca/$name.ext"
  openssl x509 -req -in "/ca/$name.csr" -CA /ca/ca.crt -CAkey /ca/ca.key -CAcreateserial -out "$target/$name.crt" -days 7 -sha256 -extfile "/ca/$name.ext"
}
issue greenmail /mail
issue web /web
openssl pkcs12 -export -in /mail/greenmail.crt -inkey /mail/greenmail.key -certfile /ca/ca.crt -out /mail/greenmail.p12 -passout pass:orbit-fixture-keystore
rm /mail/greenmail.key /mail/greenmail.crt
cp /ca/ca.crt /trust/ca.crt
chmod 0444 /trust/ca.crt /mail/greenmail.p12 /web/web.crt
# Caddy's container user needs the disposable leaf only, never the CA private key.
chmod 0444 /web/web.key
