FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY anonsurv anonsurv
COPY scripts scripts
ENV ANONSURV_CONFIG=/config DATA_DIR=/data PYTHONUNBUFFERED=1
RUN mkdir -p /data
ENTRYPOINT ["python", "-m", "anonsurv.serve"]
