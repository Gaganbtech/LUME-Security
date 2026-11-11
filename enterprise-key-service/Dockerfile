FROM python:3.12-slim

WORKDIR /app

# Install deps first for layer caching
COPY pyproject.toml .
RUN pip install --no-cache-dir -e .

# Copy source
COPY . .

# Run as non-root
RUN useradd -m appuser && chown -R appuser /app
USER appuser

EXPOSE 8100

CMD ["uvicorn", "ks.main:app", "--host", "0.0.0.0", "--port", "8100"]
