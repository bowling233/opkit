FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim

ENV PATH="/app/.venv/bin:$PATH" \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src

RUN uv sync --no-dev --no-editable && uv cache clean

EXPOSE 8000

ENTRYPOINT ["opkit"]
CMD ["--config", "/config/devices.yaml", "serve", "--transport", "streamable-http", "--host", "0.0.0.0"]
