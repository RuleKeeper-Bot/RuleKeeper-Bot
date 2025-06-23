FROM python:3.11-slim

WORKDIR /app

COPY . /app

RUN pip install --upgrade pip && pip install -r requirements.txt

# Remove .env if it exists (we use environment variables instead)
RUN rm -f .env

CMD ["python", "main.py"]
