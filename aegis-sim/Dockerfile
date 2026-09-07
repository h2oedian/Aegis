FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /simulator
COPY pyproject.toml .
COPY src ./src
RUN pip install --no-cache-dir . \
    && addgroup --system simulator \
    && adduser --system --ingroup simulator simulator \
    && chown -R simulator:simulator /simulator

USER simulator
ENTRYPOINT ["aegis-sim"]

