
FROM python:2.7

RUN apt-get update
RUN apt-get upgrade -y

RUN pip install jsbeautifier

RUN mkdir -p /lama
COPY script.py /lama/script.py
