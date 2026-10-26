FROM alpine:latest@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS alpine

ARG TARGETARCH

RUN set -eux; \
    apk add -U --no-cache ca-certificates; \
    apk add -U --no-cache tzdata


# For --generator=trivy. A static binary, so it runs on scratch
FROM aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c AS trivy


FROM scratch

ARG TARGETOS
ARG TARGETARCH

COPY --from=alpine /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=alpine /usr/share/zoneinfo /usr/share/zoneinfo
COPY dist/sbom-operator_${TARGETOS}_${TARGETARCH}*/sbom-operator /usr/local/bin/sbom-operator
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

# scratch sets no PATH, which is where the trivy generator looks
ENV PATH=/usr/local/bin

ENTRYPOINT ["/usr/local/bin/sbom-operator"]
