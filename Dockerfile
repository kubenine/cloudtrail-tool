FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY . .

# Streamlit specific configurations
ENV STREAMLIT_SERVER_PORT=8551
ENV STREAMLIT_SERVER_ADDRESS=0.0.0.0

EXPOSE 8551

CMD ["streamlit", "run", "app.py", "--server.port=8551", "--server.address=0.0.0.0"]