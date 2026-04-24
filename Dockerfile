FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY trapnet/ trapnet/
COPY setup.py .
RUN pip install --no-cache-dir -e .

COPY config.yml .

# Pre-accept legal terms so the container does not block on interactive input.
RUN touch .trapnet_accepted

RUN mkdir -p logs

# When network_mode: host is used (see docker-compose.yml), these EXPOSE
# declarations are documentation only. Ports are bound directly on the host
# network stack, not mapped through Docker. The lines remain so that
# docker inspect and tooling can see which ports this service uses.
EXPOSE 21 22 23 25 80 110 443 445 3306 3389 5432 5900 6379 11211 27017
EXPOSE 5000

CMD ["trapnet", "--config", "config.yml"]
