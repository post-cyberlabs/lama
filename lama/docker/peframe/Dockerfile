FROM python:2.7

RUN pip install simplejson
RUN pip install https://github.com/guelfoweb/peframe/archive/master.zip


# create dirs
RUN mkdir -p /lama

# copy script
COPY script.py /lama/script.py
