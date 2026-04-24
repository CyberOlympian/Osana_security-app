FROM python:3.12-slim

WORKDIR /usr/src/app

RUN useradd --create-home appuser && mkdir -p /usr/src/app

COPY requirements.txt ./
RUN python -m pip install --no-cache-dir -r requirements.txt

COPY app ./app

USER appuser

EXPOSE 5000
CMD ["python", "app/main.py"]
