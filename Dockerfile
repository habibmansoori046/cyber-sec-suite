FROM public.ecr.aws/docker/library/alpine:3.21.3
RUN apk update && apk add --no-cache python3 py3-pip sqlite && \
    ln -sf python3 /usr/bin/python && mkdir -p /root/.aws /data/docs /workspace
RUN python3 -m venv /.venv && \
    . /.venv/bin/activate && \
    python3 -m ensurepip && \
    pip3 install --no-cache --upgrade setuptools \
        strands-agents strands-agents-tools flask boto3 \
        prometheus-client && \
    pip3 install --no-cache --upgrade 'strands-agents[openai]'
RUN cp /usr/bin/python3.12 /usr/bin/sandbox_python3.12 && \
    sandbox_python3.12 -m venv /sandbox && \
    . /sandbox/bin/activate && \
    sandbox_python3.12 -m ensurepip && \
    pip3 install --no-cache --upgrade setuptools plotly pandas
WORKDIR /app
COPY src/app.py /app/
EXPOSE 5000
CMD ["sh", "-c", ". /.venv/bin/activate && python3 -u /app/app.py"]
