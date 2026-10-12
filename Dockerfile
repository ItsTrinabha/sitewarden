# syntax=docker/dockerfile:1
FROM python:3.13-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY sitewarden ./sitewarden
RUN pip install --no-cache-dir build && python -m build --wheel --outdir /dist

FROM python:3.13-slim
LABEL org.opencontainers.image.title="Sitewarden" \
      org.opencontainers.image.description="Passive website security grading: TLS, certificates, headers, cookies, content, DNSSEC and email" \
      org.opencontainers.image.licenses="MIT"
RUN useradd --system --uid 10001 --home /data sitewarden && mkdir -p /data && chown sitewarden /data
COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir "$(ls /tmp/*.whl)[web]" && rm /tmp/*.whl
USER sitewarden
WORKDIR /data
ENV SITEWARDEN_DB=/data/sitewarden.db PYTHONUNBUFFERED=1
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/api/health',timeout=4)"
ENTRYPOINT ["sitewarden"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]
