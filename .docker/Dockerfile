FROM golang:1.16-alpine AS builder

RUN apk -U --no-cache add build-base git gcc bash

WORKDIR /go/src/github.com/ory/kratos

ADD go.mod go.mod
ADD go.sum go.sum
ADD internal/httpclient/go.* internal/httpclient/

RUN go mod download

ADD . .

RUN go build -o /usr/bin/kratos

FROM alpine:3.12

RUN addgroup -S ory; \
    adduser -S ory -G ory -D -u 10000 -h /home/ory -s /bin/nologin; \
    chown -R ory:ory /home/ory

COPY --from=builder /usr/bin/kratos /usr/bin/kratos

# Exposing the ory home directory to simplify passing in Kratos configuration (e.g. if the file $HOME/.kratos.yaml
# exists, it will be automatically used as the configuration file).
VOLUME /home/ory

# Declare the standard ports used by Kratos (4433 for public service endpoint, 4434 for admin service endpoint)
EXPOSE 4433 4434

USER 10000

ENTRYPOINT ["kratos"]
CMD ["serve"]
