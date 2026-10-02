FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/juardrails ./cmd/juardrails

FROM alpine:3.22
RUN apk add --no-cache ca-certificates && addgroup -g 10001 juardrails && adduser -D -u 10001 -G juardrails -h /home/juardrails juardrails
COPY --from=build /out/juardrails /usr/local/bin/juardrails
USER 10001:10001
ENV HOME=/home/juardrails
WORKDIR /home/juardrails
ENTRYPOINT ["/usr/local/bin/juardrails"]
