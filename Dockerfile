# Official Python multi-platform image, resolved 2026-09-07.
FROM python:3.12.14-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/reference \
    UV_CACHE_DIR=/tmp/uv \
    PATH=/opt/reference/bin:${PATH} \
    PYTHONPATH=/workspace

RUN apt-get update \
    && apt-get install --yes --no-install-recommends swtpm tpm2-tools \
    && rm -rf /var/lib/apt/lists/* \
    && install -d -o 10002 -g 10002 -m 0700 /state

RUN python -m pip install --no-cache-dir uv==0.12.5
WORKDIR /workspace
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN uv sync --frozen --extra verification --no-install-project
COPY . .
RUN uv sync --frozen --extra verification --no-editable

USER 10004:10004
CMD ["python", "-m", "examples.confined_redemption.procedure"]
