#!/usr/bin/env sh

set -e

cd ./test/fixtures

rm -rf ./*.pem ./*.csr

SUBJ='/CN=api/CN=fcomb/CN=com/ST=Moscow/L=Moscow/O=End Point/OU=fcomb/emailAddress=in@fcomb.io/subjectAltName=DNS.1=fcomb.com'

openssl genrsa -out rsa.pem 2048
openssl req -subj "$SUBJ" -new -key rsa.pem -reqexts v3_req -out rsa1.csr
openssl req -subj "$SUBJ" -new -key rsa.pem -out rsa2.csr
openssl req -subj "/" -new -key rsa.pem -out rsa3.csr

openssl dsaparam 1024 -out dsaparams
openssl gendsa -out dsa.pem dsaparams
openssl req -subj "$SUBJ" -new -key dsa.pem -reqexts v3_req -out dsa1.csr
openssl req -subj "$SUBJ" -new -key dsa.pem -out dsa2.csr
openssl req -subj "/" -new -key dsa.pem -out dsa3.csr
