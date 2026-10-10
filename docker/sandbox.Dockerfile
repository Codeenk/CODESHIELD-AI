# CodeShield sandbox image (PRD §9: never run untrusted/uploaded code outside the sandbox).
#
# Used only by the verification stage when a project's unit tests should run against a
# candidate patch (FR-22). Intended to be launched with no network and read-only mounts:
#
#   docker run --rm --network none --read-only \
#       -v "$PWD/target:/work:ro" codeshield-sandbox:latest sh -lc 'cd /work && pytest -q'
#
# Adapted from the strix container approach (containers/Dockerfile) but scoped to running a
# project's own test-suite, not to pentesting live targets.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends git build-essential \
    && rm -rf /var/lib/apt/lists/*

# Runtimes commonly needed to execute tests for supported languages (FR-1 languages).
RUN pip install pytest pytest-cov \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 10002 sandbox
USER sandbox
WORKDIR /work

# No entrypoint: the caller supplies the exact test command.
CMD ["sh", "-lc", "echo 'mount a project at /work and pass a test command'"]
