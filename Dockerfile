FROM python:3.7-slim

WORKDIR /app

RUN apt-get update && apt-get install -y iputils-ping && rm -rf /var/lib/apt/lists/*

COPY . .
RUN pip install -r requirements.txt

EXPOSE 5000
CMD ["python", "app/app.py"]
