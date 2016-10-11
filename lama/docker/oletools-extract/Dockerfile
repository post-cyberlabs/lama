FROM python:2.7

RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install unzip

RUN mkdir -p /lama

RUN wget https://bitbucket.org/decalage/oletools/get/8d444c56ebcc.zip -O /tmp/decalage-oletools-8d444c56ebcc.zip
RUN unzip /tmp/decalage-oletools-8d444c56ebcc.zip -d /lama
RUN mv /lama/decalage-oletools-8d444c56ebcc /lama/oletools


COPY script.py /lama/script.py
