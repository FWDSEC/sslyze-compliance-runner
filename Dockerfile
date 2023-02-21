FROM python:3.8.16-slim-bullseye@sha256:79ec9c49fc0f231eff17bb9c109464c4c2e880ce2466825e9e348efc0a20ed96

RUN pip install --upgrade pip setuptools wheel
RUN pip install --upgrade sslyze

WORKDIR /opt
COPY main.py main.py

ENTRYPOINT [ "python", "main.py" ]