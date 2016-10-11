FROM python:3

RUN apt-get update
RUN apt-get upgrade -y
RUN pip install validators requests

RUN mkdir -p /lama



COPY script.py /lama/script.py
