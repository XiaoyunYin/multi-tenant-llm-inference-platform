# DEC-099 test harness only. Dependencies are the host locked venv, mounted RO.
FROM python:3.12.7-slim-bookworm@sha256:60d9996b6a8a3689d36db740b49f4327be3be09a21122bd02fb8895abb38b50d
RUN apt-get update && apt-get install -y --no-install-recommends git curl ca-certificates gcc libc6-dev procps xz-utils && rm -rf /var/lib/apt/lists/* && mkdir -p /opt/r87-probe-venv/bin && ln -s /usr/local/bin/python /opt/r87-probe-venv/bin/python
