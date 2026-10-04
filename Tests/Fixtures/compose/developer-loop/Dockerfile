FROM python-base AS dependencies
WORKDIR /build
COPY requirements.txt .
RUN --network=none mkdir -p /install && pip install --no-index --disable-pip-version-check --no-cache-dir --prefix=/install -r requirements.txt

FROM python-base
COPY --from=dependencies /install /usr/local
WORKDIR /app
COPY app/server.py ./server.py
COPY image-version.txt /image-version.txt
ENV POLL_INTERVAL_SECONDS=0.15
EXPOSE 8000
CMD ["python", "server.py"]
