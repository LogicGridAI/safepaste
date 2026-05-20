FROM python:3.12-alpine
WORKDIR /app

RUN apk add --no-cache gcc musl-dev

COPY safepaste/ /app/safepaste/
COPY setup.py /app/
COPY README.md /app/

RUN pip install --no-cache-dir -e ".[redis]" && \
    apk del gcc musl-dev

RUN adduser -D safepaste
USER safepaste

ENTRYPOINT ["safepaste"]
