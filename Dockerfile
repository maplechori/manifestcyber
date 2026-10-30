FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:0.13.6 /uv /uvx /bin/
ENV UV_PROJECT_ENVIRONMENT=/opt/venv
ENV PATH="/opt/venv/bin:$PATH"
WORKDIR /app
COPY pyproject.toml uv.lock README.md sbom_cli.py database.py parsers.py service.py remote.py api.py spdx3.py ./
RUN uv sync --locked --no-dev --no-editable
ENTRYPOINT ["sbom-cli"]
