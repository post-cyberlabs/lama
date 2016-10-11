FROM debian

RUN echo oracle-java8-installer shared/accepted-oracle-license-v1-1 select true | /usr/bin/debconf-set-selections
RUN echo "deb http://ppa.launchpad.net/webupd8team/java/ubuntu xenial main" | tee /etc/apt/sources.list.d/webupd8team-java.list
RUN echo "deb-src http://ppa.launchpad.net/webupd8team/java/ubuntu xenial main" | tee -a /etc/apt/sources.list.d/webupd8team-java.list
RUN apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys EEA14886
RUN apt-get update
RUN apt-get upgrade -y

RUN apt-get install -y oracle-java8-installer
RUN apt-get install -y oracle-java8-set-default
RUN apt-get install -y python

# download and install ffdec
RUN wget https://github.com/jindrapetrik/jpexs-decompiler/releases/download/version9.0.0/ffdec_9.0.0.deb
RUN dpkg -i ffdec_9.0.0.deb

# create dirs
RUN mkdir -p /lama
RUN mkdir -p /lama/out/extract

# copy script
COPY script.py /lama/script.py
