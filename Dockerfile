FROM python:3.12-slim-trixie AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    STEGOLAB_DATA_DIR=/data HOME=/tmp OMP_NUM_THREADS=1
RUN apt-get update && apt-get install -y --no-install-recommends \
    libimage-exiftool-perl binwalk binutils file libmagic1 pngcheck imagemagick \
    foremost tesseract-ocr tesseract-ocr-eng zbar-tools ffmpeg poppler-utils \
    steghide ruby ca-certificates \
    && gem install zsteg --version 0.2.13 --no-document \
    && rm -rf /var/lib/apt/lists/* /root/.local/share/gem
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt \
    && groupadd --gid 10001 stegolab \
    && useradd --uid 10001 --gid 10001 --no-create-home stegolab \
    && mkdir /data && chown 10001:10001 /data
COPY --chown=root:root stegolab ./stegolab
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "stegolab.app:app", "--host", "0.0.0.0", "--port", "8000", "--no-proxy-headers", "--limit-concurrency", "32", "--timeout-keep-alive", "5"]

FROM runtime AS test
USER root
COPY requirements-dev.txt .
RUN pip install -r requirements-dev.txt
COPY tests ./tests
COPY pytest.ini .
ENV PYTHONPATH=/app
USER 10001:10001
CMD ["python", "-m", "pytest", "-q", "-p", "no:cacheprovider"]
