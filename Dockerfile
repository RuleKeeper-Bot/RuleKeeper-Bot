FROM python:3.11-slim

# Install system dependencies (git for pip install from GitHub, gcc etc. if needed)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy project files
COPY . /app

# Install Python dependencies
RUN pip install --upgrade pip && pip install -r requirements.txt

# Remove .env if it exists (use environment variables instead)
RUN rm -f .env

# Run the bot
CMD ["python", "main.py"]
