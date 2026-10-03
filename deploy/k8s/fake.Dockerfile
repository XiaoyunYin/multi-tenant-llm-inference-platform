FROM python:3.12.7-slim-bookworm@sha256:60d9996b6a8a3689d36db740b49f4327be3be09a21122bd02fb8895abb38b50d
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --require-hashes -r /tmp/requirements.txt
COPY inference_platform /app/inference_platform
COPY tokenizer /app/tokenizer
ENV PYTHONPATH=/app INF011_TOKENIZER_CACHE=/app/tokenizer PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
USER 65532:65532
ENTRYPOINT ["python", "-u", "-m", "inference_platform.kind_fake"]
