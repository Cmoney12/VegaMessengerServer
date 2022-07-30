#!/bin/bash

:'create certs for server
Make sure you have openssl installed'

ssl_exists=false

# delete previous files
rm dh2048.pem
rm server.crt
rm server.csr
rm server.key
rm server.key.secure


openssl version
if [ $? -eq 0 ]; then
  ssl_exists=true
  echo "openssl found"
else
  ssl_exists=false
  echo "openssl is required"
fi



if [ "$ssl_exists" = true ]; then
  # Generate a private key
  openssl genrsa -des3 -out server.key 2048

  # Generate Certificate signing request
  openssl req -new -key server.key -out server.csr

  # Sign certificate with private key
  openssl x509 -req -days 3650 -in server.csr -signkey server.key -out server.crt

  # Remove password requirement (needed for example)
  #cp server.key server.key.secure
  #openssl rsa -in server.key.secure -out server.key

  # Generate dhparam file
  openssl dhparam -out dh2048.pem 2048
fi


