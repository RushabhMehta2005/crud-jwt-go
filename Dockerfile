# Stage 1: The 'builder' stage to compile the Go binary
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Copy dependency files and download them. This is cached for faster builds.
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of your source code
COPY . .

# Build the Go application into a single static binary
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/main .

# ---

# Stage 2: The 'final' stage to create the minimal production image
FROM alpine:latest

WORKDIR /

# Copy only the compiled binary from the 'builder' stage
COPY --from=builder /app/main /main

# Expose the port your application is listening on
EXPOSE 8080

# The command to run your application
CMD ["/main"]