FROM python:3.12-slim

WORKDIR /app
RUN pip install --no-cache-dir flask gunicorn

COPY app.py .

ENV APP_MODE=healthy
ENV PORT=8080

EXPOSE 8080

CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "--timeout", "30", "app:app"]
