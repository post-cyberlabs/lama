FROM python:2.7

RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install -y libpcap-dev pkg-config python-dev libgtk2.0-dev libnet1-dev python-magic

RUN mkdir -p /lama

RUN git clone https://github.com/urule99/jsunpack-n /lama/jsunpack-n

WORKDIR /lama/jsunpack-n/depends
RUN tar xvfz pynids-0.6.1.tar.gz
WORKDIR /lama/jsunpack-n/depends/pynids-0.6.1
RUN python setup.py build
RUN python setup.py install

WORKDIR /lama/jsunpack-n/depends
RUN tar xvfz js-1.8.0-rc1-src.tar.gz
WORKDIR /lama/jsunpack-n/depends/js-1.8.0-rc1-src
RUN make BUILD_OPT=1 -f Makefile.ref
RUN echo "export $PATH="

WORKDIR /lama/jsunpack-n/depends
RUN tar xvfz yara-1.6.tar.gz
WORKDIR /lama/jsunpack-n/depends/yara-1.6
RUN ./configure
RUN make
RUN make install
RUN echo "/usr/local/lib" >> /etc/ld.so.conf
RUN ldconfig

WORKDIR /lama/jsunpack-n/depends
RUN tar xvfz yara-python-1.6.tar.gz
WORKDIR /lama/jsunpack-n/depends/yara-python-1.6
RUN python setup.py build
RUN python setup.py install

WORKDIR /lama/jsunpack-n/depends
RUN tar xvfz BeautifulSoup-3.2.0.tar.gz
WORKDIR /lama/jsunpack-n/depends/BeautifulSoup-3.2.0/
RUN python setup.py build
RUN python setup.py install

WORKDIR /lama/jsunpack-n/depends
RUN tar xvfz pycrypto-2.4.1.tar.gz
WORKDIR /lama/jsunpack-n/depends/pycrypto-2.4.1
RUN python setup.py build
RUN python setup.py install

RUN chmod +x /lama/jsunpack-n/jsunpackn.py


COPY script.py /lama/script.py

WORKDIR /lama/jsunpack-n/
