FROM python

RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install -y mime-support unrar-free
RUN pip install pyunpack patool python-magic rarfile

RUN mkdir -p /lama



COPY script.py /lama/script.py
