FROM golang:1.18 as builder

ADD https://github.com/optiv/Mangle/releases/download/v1.0/Mangle_1.0_linux_amd64 mangle

RUN chmod +x /go/mangle

RUN mkdir /go/payloads
