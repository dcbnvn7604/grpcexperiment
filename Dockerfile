FROM python:3.8-slim

COPY . /grpc

WORKDIR /grpc

RUN pip install pipenv
RUN pipenv install --system

ENTRYPOINT ["bash"] 