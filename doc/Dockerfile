FROM ubuntu:focal

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -yq \
  docbook \
  docbook-xml \
  docbook-xsl \
  xsltproc \
  doxygen \
  libsaxonhe-java \
  default-jre-headless \
  git \
  g++ \
  python

COPY entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
