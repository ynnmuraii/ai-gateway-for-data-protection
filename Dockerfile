# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
FROM node:22.20.0-bookworm-slim@sha256:b21fe589dfbe5cc39365d0544b9be3f1f33f55f3c86c87a76ff65a02f8f5848e AS frontend
WORKDIR /build/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM ghcr.io/astral-sh/uv:0.9.2@sha256:6dbd7c42a9088083fa79e41431a579196a189bcee3ae68ba904ac2bf77765867 AS uv
FROM python:3.11.14-slim-bookworm@sha256:65a93d69fa75478d554f4ad27c85c1e69fa184956261b4301ebaf6dbb0a3543d
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    UV_PYTHON_DOWNLOADS=never UV_LINK_MODE=copy \
    PATH=/app/.venv/bin:$PATH PYTHONPATH=/app/backend
COPY --from=uv /uv /usr/local/bin/uv
COPY pyproject.toml uv.lock ./
# Locked wheel URLs and SHA256 hashes include both offline NLP models.
RUN uv sync --frozen --no-dev --no-install-project
COPY backend/ ./backend/
# Keep migration resources beside the module as well as the installation script.
RUN cp -r backend/migrations backend/gateway/migrations \
    && groupadd --gid 10001 gateway && useradd --uid 10001 --gid gateway --no-create-home gateway
COPY --from=frontend /build/frontend/dist ./frontend/dist
COPY scripts/bootstrap-compose.py scripts/connect-openwebui.py ./scripts/
USER gateway
EXPOSE 8000
CMD ["uvicorn", "gateway.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--no-access-log"]
