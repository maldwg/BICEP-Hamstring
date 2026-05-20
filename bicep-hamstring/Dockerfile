ARG BASE_IMAGE
ARG VERSION
FROM ${BASE_IMAGE}:${VERSION}

RUN mkdir /opt/code
WORKDIR /opt/code

COPY ./requirements.txt /opt/code/requirements.txt
COPY ./apt-requirements.txt /tmp/apt-requirements.txt
COPY ./src/ /opt/code/src

# path to locate the IDSBase implementation
ENV IDS_MODULE=src.models.hamstring
ENV IDS_CLASS=Hamstring
ENV CONFIGURATION_DEFAULT_LOCATION=/app/config.yaml
ENV HAMSTRING_ZEEK_BINARY=/opt/hamstring_zeek
ENV CONTAINER_NAME=zeek1

RUN apt-get update \
    && xargs -a /tmp/apt-requirements.txt apt-get install -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*
RUN python3 -m venv /opt/bicep-venv
ENV PATH="/opt/bicep-venv/bin:${PATH}"
RUN pip install --no-cache-dir -r requirements.txt

CMD [ "/bin/bash","-c","fastapi dev /opt/code/src/main.py --host 0.0.0.0 --port ${PORT}" ]
