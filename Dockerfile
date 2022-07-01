FROM python:3.8-slim

RUN pip install pipenv

WORKDIR /grpc

ENTRYPOINT ["bash"] 