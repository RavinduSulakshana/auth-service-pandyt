# Stage 1: Builder
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code
COPY . .

# Build the Go application
RUN go build -o main .

# Stage 2: Runner
FROM alpine:latest

# Install sqlite dependencies
RUN apk --no-cache add sqlite

WORKDIR /app

# Copy the built binary from the builder stage
COPY --from=builder /app/main .

# Copy the .env file and the database file
COPY .env .
COPY auth.db .

# Expose the port the app runs on
EXPOSE 8080

# Command to run the executable
CMD ["./main"]
