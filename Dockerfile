# forge-nodehub-Image (Design 3.1). In Slice N1 wird dieses Image NICHT gebaut und nichts gestartet - der Bau gehoert zum Install (N4, Owner).
# Basis: das digest-gepinnte forge-core-App-Image (Python 3.12 + psycopg/pool); hinzu kommt nur openssh-client (ssh-keygen -Y fuer Signatur/Pruefung, Design 3.1).
#   docker build --build-arg BASE_IMAGE=$IMG_FORGE_CORE_APP -t forge-node/hub:build .
ARG BASE_IMAGE
FROM ${BASE_IMAGE} AS nodehub
USER root
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client && rm -rf /var/lib/apt/lists/*
ARG FORGE_UID=994
ARG FORGE_GID=981
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 HOME=/tmp PYTHONPATH=/app/src FORGE_NODE_MIGRATIONS_DIR=/app/migrations FORGE_NODEHUB_CONTAINER=1
WORKDIR /app
COPY src/forge_node ./src/forge_node
COPY migrations ./migrations
USER ${FORGE_UID}:${FORGE_GID}
CMD ["python", "-m", "forge_node.hub"]
