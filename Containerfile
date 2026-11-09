# Pinned to the same patch release as rust-toolchain.toml so rustup never
# has to download a toolchain during the build.
FROM docker.io/library/rust:1.99.1-trixie AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
# Warm dependencies for both targets before copying application sources.
RUN mkdir src && printf 'fn main(){}\n' > src/main.rs && touch src/lib.rs \
    && cargo build --release --locked --bin judex && rm -rf src
COPY src/ src/
COPY assets/ assets/
# Invalidate the stub fingerprints even when COPY preserves older timestamps.
RUN find src -type f -exec touch {} + \
    && cargo build --release --locked --bin judex

FROM gcr.io/distroless/cc-debian13:nonroot AS runtime
ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.source="https://github.com/jtr860830/judex" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$REVISION" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.description="Turns container image vulnerability scans into audit reports"
COPY --from=build /src/target/release/judex /usr/local/bin/judex
COPY LICENSE THIRD_PARTY_NOTICES.md /usr/share/doc/judex/
COPY assets/fonts/LICENSE-*.txt /usr/share/doc/judex/fonts/
USER 65532:65532
WORKDIR /output
VOLUME ["/output"]
ENTRYPOINT ["/usr/local/bin/judex"]
CMD ["run", "--config", "/etc/report/config.yaml"]
