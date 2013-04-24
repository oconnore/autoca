
# AutoCA
## A tool for managing x509 certificates

This is a short Python script for managing a set of certificates and keys.

    $ autoca init
    
    $ autoca mkca -a demo-ca -n 'Demo CA' -e
    Password for CA key: 
    please verify: 
    
    $ autoca mkcert -a demo-ca -s 'first' -n 'First Common Name' -e
    Password for new key: 
    please verify: 
    Password for CA key: 
    
    $ find demo-ca/
    demo-ca/
    demo-ca/serial.txt
    demo-ca/demo-ca-cert.pem
    demo-ca/demo-ca-key.pem
    demo-ca/certs
    demo-ca/certs/first
    demo-ca/certs/first/first-key.pem
    demo-ca/certs/first/first-csr.pem
    demo-ca/certs/first/first-cert.pem
