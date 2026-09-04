# HAAP Public Directory — single-container image (SPEC §6.1, §7 F6).
FROM python:3.11-slim

# Optional: dnspython enables the L2 dns_txt verification method. The
# https_well_known method works without it.
ARG WITH_DNS=1

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY haap_dird.py ./

RUN pip install --no-cache-dir . \
    && if [ "$WITH_DNS" = "1" ]; then pip install --no-cache-dir dnspython; fi

# Persist the SQLite index + directory key on a mounted volume.
VOLUME ["/data"]
ENV HAAP_DIRD_DB_PATH=/data/dird.db \
    HAAP_DIRD_HOST=0.0.0.0 \
    HAAP_DIRD_PORT=8444
EXPOSE 8444

# Run as a non-root user; /data must be writable by uid 10001 at runtime.
RUN useradd --uid 10001 --create-home haap && mkdir -p /data && chown haap /data
USER haap

ENTRYPOINT ["haap-dird"]
CMD ["--db", "/data/dird.db", "--host", "0.0.0.0", "--port", "8444"]
