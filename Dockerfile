# authz-service image (M12 -- see plan.md Section 5).
# Multi-stage: build deps in one layer, run as non-root in a slim final
# image. Mirrors bedrock-gateway-app's Dockerfile.
# policies/iam_tenants.yaml is required at startup (FileIamTenantResolver)
# unless PROVISIONED_PRINCIPAL_MAPPINGS_TABLE_NAME is set and every
# principal is provisioned there instead.

FROM python:3.11-slim AS builder

WORKDIR /build
COPY pyproject.toml poetry.lock ./
ENV VIRTUAL_ENV=/opt/venv \
    PATH=/opt/venv/bin:$PATH
RUN python -m venv /opt/venv \
    && pip install --no-cache-dir 'poetry==2.1.4' \
    && poetry install --only main --no-root

FROM python:3.11-slim

RUN groupadd --gid 1000 app && useradd --uid 1000 --gid app --shell /bin/bash --create-home app

COPY --from=builder /opt/venv /opt/venv
WORKDIR /app
COPY services/ ./services/
COPY policies/ ./policies/
RUN chown -R app:app /app

USER app
EXPOSE 8080

ENV AUTHZ_HOST=0.0.0.0 \
    AUTHZ_PORT=8080 \
    PATH=/opt/venv/bin:$PATH \
    PYTHONUNBUFFERED=1

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).status==200 else 1)"

CMD ["uvicorn", "services.authz.main:app", "--host", "0.0.0.0", "--port", "8080"]
