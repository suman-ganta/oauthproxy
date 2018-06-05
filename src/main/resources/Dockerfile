# Pull base image
# ---------------
FROM ${docker.repository}/jdk:8

# Maintainer
# ----------
MAINTAINER Suman Ganta <suman.g.ganta@oracle.com>


# Environment variables required for this build (do NOT change)
# -------------------------------------------------------------

ENV ORACLE_HOME=/oic/oauthproxy \
    PATH=$PATH:/usr/java/default/bin: \
    LANG="en_US.UTF-8" \
    LC_ALL="en_US.UTF-8"

# Configure shaded jar
# ------------------------------------------------------------
COPY ${build.finalName}.${packaging}  /oic/oauthproxy/
COPY Dockerfile  /oic/oauthproxy/

# Setup filesystem and oracle user
# ------------------------------------------------------------
RUN chmod a+xr /oic/oauthproxy && \
    useradd -b /oic/oauthproxy -m -s /bin/bash oracle && \
    echo oracle:oracle | chpasswd

RUN chown oracle:oracle -R /oic

USER oracle

WORKDIR $ORACLE_HOME

# Define default command to start bash.
ENTRYPOINT ["java", "-jar", "oauthproxy-1.0-SNAPSHOT.jar"]
