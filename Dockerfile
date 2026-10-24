# SQLGuard Ninja playground server (validation + restricted synthetic sandbox).
#
#   docker build -t sqlguard-ninja-demo .
#   docker run --rm -p 127.0.0.1:8000:8000 --read-only --cap-drop ALL \
#     --security-opt no-new-privileges sqlguard-ninja-demo
#
# The image holds no credentials and connects to no database: the demo data is synthetic and
# generated in memory at start-up. Settings: SQLNINJA_DEMO_* (see docs/guides/DEPLOYMENT.md).

ARG PYTHON_IMAGE=python:3.12-slim@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704

FROM ${PYTHON_IMAGE} AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE THIRD_PARTY_NOTICES.md CHANGELOG.md ./
COPY src ./src
COPY benchmarks/datasets ./benchmarks/datasets
COPY benchmarks/policies ./benchmarks/policies
RUN python -m pip install --no-cache-dir --upgrade "build>=1.2" \
 && python -m build --wheel --outdir /dist \
 && python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir "$(ls /dist/*.whl)[demo]"

FROM ${PYTHON_IMAGE}
LABEL org.opencontainers.image.title="SQLGuard Ninja playground" \
      org.opencontainers.image.source="https://github.com/Pratik653/SQLGuard_Ninjapy" \
      org.opencontainers.image.licenses="Apache-2.0"
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SQLNINJA_DEMO_EXECUTE=true \
    SQLNINJA_DEMO_RATE_LIMIT_PER_MINUTE=60
COPY --from=build /opt/venv /opt/venv
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin sqlninja
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"]
CMD ["sqlninja", "demo", "serve", "--host", "0.0.0.0", "--port", "8000"]
