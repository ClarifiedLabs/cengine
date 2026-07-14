FROM mirror.gcr.io/library/alpine@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
COPY marker.txt /marker.txt
RUN mkdir -p /workspace && printf copied-from-image >/workspace/seed
CMD ["cat", "/marker.txt"]
