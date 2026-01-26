FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y \
    build-essential \   
    libpq-dev \       
    postgresql-client \     
    && rm -rf /var/lib/apt/lists/*


COPY requirements.txt .

RUN pip3 install --upgrade pip \
    && pip3 install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000


CMD ["gunicorn", "core.wsgi:application", "--bind", "0.0.0.0:8000", "--graceful-timeout", "30", "--timeout", "60"]



