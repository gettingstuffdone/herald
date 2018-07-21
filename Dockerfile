FROM        ubuntu:16.04
MAINTAINER  Lino

ENV DEBIAN_FRONTEND noninteractive

# Update apt sources
#RUN echo "deb http://archive.ubuntu.com/ubuntu precise main universe" > /etc/apt/sources.list

# Update the package repository
# RUN apt-get -qq update

# Install base system
#RUN apt-get install -y varnish vim git

# Make our custom VCLs available on the container
#ADD default.vcl /etc/varnish/default.vcl

# Export environment variables
#ENV VARNISH_PORT 80

# Expose port 80
# EXPOSE 80
RUN apt-get update && apt-get install -y python3 python3-pip && pip3 install setuptools && mkdir /herald
COPY . /herald/

# COPY scripts/herald.service /etc/systemd/system/
WORKDIR /herald

RUN python3 setup.py install

ENTRYPOINT ["/usr/local/bin/herald"]