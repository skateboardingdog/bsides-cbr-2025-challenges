FROM golang:1.25-alpine AS builder

RUN addgroup -g 1000 -S appuser && \
    adduser -u 1000 -S appuser -G appuser

WORKDIR /app

COPY go.mod go.sum main.go ./

RUN go mod download && go build -o server main.go

FROM postgres:17-alpine
WORKDIR /app
COPY --from=builder /app/server /app/
COPY index.html start.sh /app/
RUN addgroup -S appuser && adduser -S appuser -G appuser
RUN chown -R appuser:appuser /app
COPY init.sql /docker-entrypoint-initdb.d/init.sql

EXPOSE 1337

ENTRYPOINT [ "/app/start.sh" ]