FROM python:3.12-slim
LABEL org.opencontainers.image.title="cognis-mftparse"
LABEL org.opencontainers.image.source="https://github.com/cognis-digital/mftparse"
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir .
ENTRYPOINT ["mftparse"]
