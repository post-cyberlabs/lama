FROM python:2.7

RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install -y libemu2 libemu-dev python-crypto git


RUN pip install pillow pylibemu pycrypto slowaes pexpect
RUN pip install -e git+https://github.com/taguchimail/pyv8-linux-x64.git#egg=pyv8

RUN mkdir -p /lama
RUN git clone https://github.com/jesparza/peepdf/ /lama/peepdf/
COPY script.py /lama/script.py
