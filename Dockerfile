FROM golang:1.24.4-alpine3.21 as builder

WORKDIR /opt/src
ADD . /opt/src
RUN go build -o /opt/auth_proxy .


FROM alpine:3.21

WORKDIR /opt
ADD config /opt/config
ADD static /opt/static

COPY --from=builder /opt/auth_proxy /opt/auth_proxy
RUN chown -R root:nobody /opt

EXPOSE 8080
USER nobody
ENTRYPOINT ["/opt/auth_proxy"]
