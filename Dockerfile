FROM python:3.12-slim-trixie AS dependencies
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    STEGOLAB_DATA_DIR=/data HOME=/tmp OMP_NUM_THREADS=1
RUN apt-get update && apt-get install -y --no-install-recommends \
    libimage-exiftool-perl binwalk binutils file libmagic1 pngcheck imagemagick \
    foremost tesseract-ocr tesseract-ocr-eng zbar-tools ffmpeg poppler-utils \
    steghide ruby ca-certificates sox libsox-fmt-all \
    && gem install zsteg --version 0.2.13 --no-document \
    && rm -rf /var/lib/apt/lists/* /root/.local/share/gem
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt \
    && groupadd --gid 10001 stegolab \
    && useradd --uid 10001 --gid 10001 --no-create-home stegolab \
    && mkdir /data && chown 10001:10001 /data
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "stegolab.app:app", "--host", "0.0.0.0", "--port", "8000", "--no-proxy-headers", "--limit-concurrency", "32", "--timeout-keep-alive", "5"]

FROM dependencies AS runtime
COPY --chown=root:root stegolab ./stegolab
COPY --chown=root:root config/imagemagick-policy.xml /etc/ImageMagick-7/policy.xml

FROM runtime AS test
USER root
COPY requirements-dev.txt .
RUN pip install -r requirements-dev.txt
COPY tests ./tests
COPY pytest.ini .
ENV PYTHONPATH=/app
USER 10001:10001
CMD ["python", "-m", "pytest", "-q", "-p", "no:cacheprovider"]

FROM dependencies AS specialized-build
USER root
RUN apt-get update && apt-get install -y --no-install-recommends cmake g++ make libmhash-dev libmcrypt-dev libjpeg62-turbo-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*
COPY config/install-specialized.py /tmp/install-specialized.py
RUN python /tmp/install-specialized.py \
    && cmake -S /opt/stegseek/stegseek-0.6 -B /opt/stegseek/build -DCMAKE_BUILD_TYPE=Release \
    && cmake --build /opt/stegseek/build --target stegseek -j2 \
    && mkdir -p /opt/openstego-final \
    && find /opt/openstego -name openstego.jar -exec cp {} /opt/openstego-final/openstego.jar \;

FROM dependencies AS tools-dependencies
USER root
RUN apt-get update && apt-get install -y --no-install-recommends outguess stegsnow openjdk-21-jre-headless libexempi8 libarchive-tools \
    && rm -rf /var/lib/apt/lists/* \
    && python -m venv --system-site-packages /opt/stegoveritas \
    && /opt/stegoveritas/bin/pip install stegoveritas==1.11 \
    && /opt/stegoveritas/bin/python -c "import site,pathlib; pathlib.Path(site.getsitepackages()[0],'debian-binwalk.pth').write_text('/usr/lib/python3/dist-packages\\n')" \
    && ln -s /opt/stegoveritas/bin/stegoveritas /usr/local/bin/stegoveritas

FROM tools-dependencies AS tools
COPY --chown=root:root stegolab ./stegolab
COPY --chown=root:root config/imagemagick-policy.xml /etc/ImageMagick-7/policy.xml
COPY --from=specialized-build /opt/stegseek/build/src/stegseek /usr/local/bin/stegseek
COPY --from=specialized-build /opt/openstego-final/openstego.jar /opt/openstego/openstego.jar
COPY config/openstego /usr/local/bin/openstego
RUN chmod 755 /usr/local/bin/openstego
USER 10001:10001

FROM tools AS tools-test
USER root
COPY requirements-dev.txt .
RUN pip install -r requirements-dev.txt
COPY tests ./tests
COPY pytest.ini .
ENV PYTHONPATH=/app
USER 10001:10001
CMD ["python", "-m", "pytest", "-q", "-p", "no:cacheprovider"]
