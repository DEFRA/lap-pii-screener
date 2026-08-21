FROM eclipse-temurin:25-jdk-noble
ENV DOCKER_RUNNING="true" \
  JAVA_HOME='/opt/java/openjdk' \
  PII_SCREENER_SOURCE_DIR='/source' \
  UV_LINK_MODE=copy
RUN set -eux; \
  deluser ubuntu; \
  useradd --system --uid 1000 --gid 0 node; \
  apt-get update; \
  apt-get --no-install-recommends -y install \
  bash \
  curl \
  fonts-dejavu \
  gnupg \
  unzip; \
  echo "networkaddress.cache.ttl=5" >> "${JAVA_HOME}/conf/security/java.security"; \
  sed --in-place --expression="s?securerandom.source=file:/dev/random?securerandom.source=file:/dev/urandom?g" "${JAVA_HOME}/conf/security/java.security"; \
  for server in $(shuf -e hkps://keyserver.ubuntu.com) ; do \
  gpg --batch --keyserver "${server}" --recv-keys 679F1EE92B19609DE816FDE81DB198F93525EC1A && break || : ; \
  done; \
  curl -LsSf https://astral.sh/uv/install.sh | UV_INSTALL_DIR=/usr/local/bin sh
VOLUME ["/home/node/lap-pii-screener", "/source", "/home/node/.sensitive-scanner", "/home/node/.cache/uv", "/home/node/.local/share/uv/python"]
USER node
WORKDIR /home/node/lap-pii-screener
CMD ["/bin/bash"]
