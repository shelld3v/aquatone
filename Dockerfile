FROM golang:latest

RUN apt-get update &&
apt-get install -yq chromium

#install aquatone binary
WORKDIR /opt/aquatone
RUN go get github.com/shelld3v/aquatone && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["aquatone"]
