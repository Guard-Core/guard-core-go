# Build context is the repository root (see docker-compose.yml):
#   docker build -f examples/simple_app/Dockerfile .
FROM golang:1.26-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY guardcore/ guardcore/
COPY examples/simple_app/ examples/simple_app/

RUN CGO_ENABLED=0 go build -trimpath -o /out/simple_app ./examples/simple_app

FROM alpine:3.22

RUN adduser -D -H guard

COPY --from=build /out/simple_app /usr/local/bin/simple_app

USER guard

EXPOSE 8080

ENTRYPOINT ["simple_app"]
