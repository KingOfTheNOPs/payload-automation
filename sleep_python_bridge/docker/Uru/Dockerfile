FROM golang:1.18 as builder

COPY . ./

RUN mkdir /go/payloads
#RUN mkdir /go/configs

ADD https://github.com/guervild/uru/releases/download/v0.0.2/uru_0.0.2_linux_386.tar.gz uru.tar.gz 
RUN tar -xf uru.tar.gz 2>/dev/null
RUN go install mvdan.cc/garble@latest
RUN git clone https://github.com/C-Sto/BananaPhone

RUN cd BananaPhone; go mod download