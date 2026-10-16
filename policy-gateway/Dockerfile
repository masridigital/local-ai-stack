FROM docker.io/library/python:3.12-slim-bookworm@sha256:2ed6491b93cd49272ee6de2b5a38440c3448360322c089fc23e370722d74179d

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN useradd --uid 65532 --create-home --shell /usr/sbin/nologin appuser \
    && mkdir -p /app \
    && chown appuser:appuser /app

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY stack /app/stack
COPY litellm/policy.yaml /app/litellm/policy.yaml
COPY presidio/recognizers /app/presidio/recognizers

USER 65532:65532
EXPOSE 8088
CMD ["python", "-m", "stack.server"]
