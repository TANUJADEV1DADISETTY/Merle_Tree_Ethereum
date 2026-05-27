FROM python:3.11-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc python3-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Runtime ──────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

LABEL description="Merkle Tree implementation to verify Ethereum transactions"

WORKDIR /app

COPY --from=builder /install /usr/local

COPY part1_tree.py part2_fetch.py part3_verify.py ./

ENV ETH_RPC_URL=""
ENV ETH_BLOCK_NUMBER="latest"
ENV ETH_TX_INDEX="0"

CMD ["python", "part3_verify.py"]
