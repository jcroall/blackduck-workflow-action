FROM openjdk:slim
COPY --from=python:slim / /
#FROM python:slim

ADD blackduck-scan.py /blackduck-scan.py
#RUN apt-get update && apt-get install -y --no-install-recommends wget
#RUN wget -O detect.sh https://detect.synopsys.com/detect7.sh
RUN apt-get update && apt-get install -y --no-install-recommends curl
RUN curl -s -L https://detect.synopsys.com/detect7.sh -o /detect.sh

RUN pip install --upgrade pip
#RUN pip install PyGithub

WORKDIR /app

ENTRYPOINT ["/blackduck-scan.py"]
