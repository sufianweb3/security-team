# Optional hardened runtime for the deterministic engine + tools.
# The LLM harness runs on the host; point its shell at `docker compose run auditor ...`
# if you want the tools sandboxed in a container (see docs/SETUP.md#docker).
# Pin the base image by digest in production: docker pull python:3.12-slim && docker inspect --format '{{index .RepoDigests 0}}'
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1 SEMGREP_SEND_METRICS=off
RUN useradd --create-home --uid 10001 auditor
WORKDIR /opt/sentinel
COPY requirements.txt scripts/install_tools.py ./
RUN pip install -r requirements.txt \
 && mkdir -p scripts && mv install_tools.py scripts/ \
 && python scripts/install_tools.py \
 && chown -R auditor:auditor /opt/sentinel
COPY --chown=auditor:auditor . .
USER auditor
ENV PATH="/opt/sentinel/tools/bin:${PATH}" SENTINEL_ROOT=/opt/sentinel
ENTRYPOINT ["python", "-m", "auditor"]
