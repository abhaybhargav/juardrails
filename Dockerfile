FROM golang:1.26.8-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/juardrails ./cmd/juardrails

FROM alpine:3.23
RUN apk add --no-cache ca-certificates && addgroup -S juardrails && adduser -S -G juardrails juardrails && mkdir /data && chown juardrails:juardrails /data
USER juardrails
COPY --from=build /out/juardrails /usr/local/bin/juardrails
EXPOSE 8080
VOLUME /data
ENTRYPOINT ["juardrails"]
CMD ["-addr", "0.0.0.0:8080", "-db", "/data/juardrails.sqlite", "-audit-log", "/data/audit.jsonl"]
