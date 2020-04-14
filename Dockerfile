FROM golang:1.13-buster
RUN apt update
RUN apt install wget build-essential libssl-dev cmake libseccomp-dev softhsm git -y
RUN mkdir -p /var/lib/softhsm/tokens
RUN softhsm2-util --init-token --slot 0 --label hsm --pin 1234 --so-pin 1234
COPY ./ /app
WORKDIR /app
RUN go mod tidy
