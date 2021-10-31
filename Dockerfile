FROM openjdk:slim
COPY --from=python:slim / /
#FROM python:slim

ADD blackduck-workflow.py /blackduck-workflow.py

RUN pip install --upgrade pip
#RUN pip install PyGithub

WORKDIR /app

ENTRYPOINT ["/blackduck-workflow.py"]
