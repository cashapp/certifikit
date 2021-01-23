Certifikit
==========

_An ergonomic CLI for understanding certificates._

cft is an ergonomic CLI which allows you to understand your certificates
on disk via Certifikit.

## Run in local testing

```
$ ./cft -V
cft 0.1.0-SNAPSHOT
```

## Install locally via homebrew

```
./brew-install.sh
```

Unofficial binaries available with `brew install yschimke/tap/cft` for mac and linux.

## Show a certificate from URL

```
$ cft https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem  
```

![image](https://user-images.githubusercontent.com/231923/100985934-744a3280-3544-11eb-9e95-e8a38e5a0df0.png)

## Downloading certificates

```
$ cft --ouput /tmp/certs --host api.twitter.com
```

## Querying a host

```
$ cft --host api.twitter.com
```

![image](https://user-images.githubusercontent.com/231923/100985491-f4bc6380-3543-11eb-8664-b101ee26eb54.png)
