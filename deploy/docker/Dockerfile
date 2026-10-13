# syntax=docker/dockerfile:1
# Runtime image assembled by GoReleaser from binaries it has already built
# (see .goreleaser.yaml). It is not meant for `docker build` from a checkout.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3

ARG TARGETPLATFORM

# Data directory for the SQLite database, owned by the unprivileged user so a
# named volume mounted here inherits the right ownership.
COPY --chown=65532:65532 <<EOT /var/lib/clavis/README
This directory holds the Clavis SQLite database when database.driver is sqlite.
EOT

COPY $TARGETPLATFORM/clavis /usr/bin/clavis

ENV CLAVIS_SERVER_ADDRESS=:8080 \
    CLAVIS_DATABASE_DSN=/var/lib/clavis/clavis.db \
    CLAVIS_TELEMETRY_METRICS_ADDRESS=:9464

WORKDIR /var/lib/clavis
USER 65532:65532
EXPOSE 8080 9464
ENTRYPOINT ["/usr/bin/clavis"]
CMD ["serve"]
