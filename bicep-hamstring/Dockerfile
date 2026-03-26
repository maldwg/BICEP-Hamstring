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

RUN python3.13 -m pip install -r requirements.txt
RUN xargs apt install -y < /tmp/apt-requirements.txt

CMD [ "/bin/bash","-c","fastapi dev /opt/code/src/main.py --host 0.0.0.0 --port ${PORT}" ]
