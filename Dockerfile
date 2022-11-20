FROM golang:1.19 AS build
WORKDIR /build
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get upgrade -y && apt-get install ca-certificates
RUN git clone https://github.com/coredns/coredns && \
    cd /build/coredns && sed -i '/^hosts:hosts/i coredyndns:github.com/ro0p/coredyndns' plugin.cfg
RUN cd /build/coredns && go get -u ./...
RUN echo "!"
RUN cd /build/coredns && go get github.com/ro0p/coredyndns
RUN cd /build/coredns && go generate && go build

FROM scratch
COPY --from=build /build/coredns/coredns /coredns
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
EXPOSE 53 53/udp
ENTRYPOINT ["/coredns"]