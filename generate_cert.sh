#!/bin/zsh
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes \
  -subj "/C=IN/ST=State/L=City/O=Development/CN=localhost"
