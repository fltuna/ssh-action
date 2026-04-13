FROM golang:1.25 AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o /ssh-action .

FROM scratch
COPY --from=builder /ssh-action /ssh-action
ENTRYPOINT ["/ssh-action"]
