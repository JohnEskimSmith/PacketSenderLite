FROM python:3.8-slim
WORKDIR /usr/src/app
COPY . .

# gcc with friends for ujson
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc python-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip install -r requirements.txt
RUN apt-get purge -y --auto-remove gcc python-dev
CMD ["python", "packetsenderlite.py"]