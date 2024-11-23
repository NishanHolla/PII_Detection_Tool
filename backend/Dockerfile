# Use the official slim Python image
FROM python:3.9-slim

# Set environment variables to prevent Python from writing .pyc files
# and to ensure that the output is flushed immediately
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set the working directory in the container
WORKDIR /app

# Copy requirements.txt into the container
COPY requirements.txt .

# Upgrade pip and install system dependencies required for some packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libssl-dev \
    && pip install --upgrade pip setuptools \
    && pip install numpy==1.21.4 \
    && pip install --no-cache-dir -r requirements.txt \
    && apt-get remove --purge -y gcc libffi-dev libssl-dev \
    && apt-get autoremove -y \
    && apt-get clean

# Download the spaCy model
RUN python -m spacy download en_core_web_sm

# Copy the rest of your application code into the container
COPY . .

# Expose the port that your app runs on
EXPOSE 8000

# Command to run your FastAPI app with Uvicorn
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
