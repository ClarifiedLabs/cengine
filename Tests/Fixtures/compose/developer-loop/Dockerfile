FROM mirror.gcr.io/library/python@sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0 AS dependencies
WORKDIR /build
COPY requirements.txt .
RUN mkdir -p /install && pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM mirror.gcr.io/library/python@sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0
COPY --from=dependencies /install /usr/local
WORKDIR /app
COPY app/server.py ./server.py
COPY image-version.txt /image-version.txt
ENV POLL_INTERVAL_SECONDS=0.15
EXPOSE 8000
CMD ["python", "server.py"]
