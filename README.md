# coredyndns
[![Go](https://github.com/ro0p/coredyndns/actions/workflows/go.yml/badge.svg)](https://github.com/ro0p/coredyndns/actions/workflows/go.yml)

Dynamic DNS plugin for [CoreDNS](https://github.com/coredns/coredns)

## Description

The *coredyndns* plugin is a simplified DynDNSv2 API server. It accepts HTTP update requests and answers DNS queries for registered hostnames. It only supports A and AAAA records.

## DynDNS update

Clients can update their IP address by calling an URL in the following form:

~~~
http(s)://[username:password@]<server name>:<port>/update?hostname=<hostname>[&myip=<ip address>]
~~~
If *myip* parameter is not set the remote address of caller will be used in DNS

## Syntax

~~~
coredyndns [zones...] {
	[listen :9080 [tls [insecure]]]
	[cert file <filename>]
	[key file <filename>]
	[username <username>]
	[password <password>]
}
~~~

* **zones** allowed zones for dynamic update. If not set all zones served by CoreDNS are allowed.
* **listen** HTTP server parameters. The default listening port is *9080* without TLS.
**tls** use TLS (HTTPS) protocol. **cert** and **key** must be set too
**insecure** accepts any certificate
* **cert**, **key** TLS certificate and private key in PEM format
* **username**, **password** HTTP BasicAuth, both must be set to use authentication

## Examples

Using default configuration, and accepts all zones

~~~ corefile
. {
    coredyndns
}
~~~

Using default configuration, but only `example.com` zone is allowed

~~~
. {
    coredyndns example.com
}
~~~

Listens on custom port with insecure TLS and authentication is not required

~~~
. {
    coredyndns example.com {
        listen :99 tls insecure
        cert file ./cert.pem
        key file ./key.pem
    }
}
~~~
