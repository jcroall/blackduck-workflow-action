FROM openjdk:slim
COPY --from=python:slim / /
#FROM python:slim

ADD blackduck-workflow.py /blackduck-workflow.py
ADD blackduck-rapid-scan-to-sarif-bdio.py /blackduck-rapid-scan-to-sarif-bdio.py

RUN pip install --upgrade pip && pip install PyGithub networkx blackduck

WORKDIR /app

ENTRYPOINT ["/blackduck-workflow.py"]
