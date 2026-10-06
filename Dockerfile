FROM rust:1.85-bookworm AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y \
    softhsm2 \
    libsofthsm2 \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/lib/softhsm/tokens
RUN echo "directories.tokendir = /var/lib/softhsm/tokens\nobjectstore.backend = file" > /etc/softhsm2.conf

RUN softhsm2-util --init-token --slot 0 --label "arkion-token" --so-pin 123456 --pin 1234

COPY --from=builder /app/target/release/hsm-backend-signing-service /usr/local/bin/

EXPOSE 8080

ENV PKCS11_LIB_PATH=/usr/lib/softhsm/libsofthsm2.so
ENV HSM_PIN=1234
ENV HSM_SLOT=0
ENV RUST_LOG=info

CMD ["hsm-backend-signing-service"]