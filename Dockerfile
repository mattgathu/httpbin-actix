# syntax=docker/dockerfile:experimental
FROM rust:latest as base

RUN apt-get update && apt-get install musl-tools -y
RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /app

COPY Cargo.toml Cargo.lock ./

RUN mkdir src/ && \
    echo "fn main() {eprintln!(\"if you see this, the build broke\")}" > src/main.rs && \
    cargo build --target=x86_64-unknown-linux-musl --release && \
    rm -rf target/x86_64-unknown-linux-musl/release/.fingerprint/httpbin-actix-*

COPY . .

RUN cargo build --target=x86_64-unknown-linux-musl --release

FROM alpine as runtime

COPY --from=base /app/target/x86_64-unknown-linux-musl/release/httpbin-actix /server

EXPOSE 80

CMD ./server
