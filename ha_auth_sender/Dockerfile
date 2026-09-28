ARG BUILD_FROM
FROM $BUILD_FROM

COPY ha_auth_sender.py /opt/ha_auth_sender/ha_auth_sender.py
COPY s6-overlay/s6-rc.d /etc/s6-overlay/s6-rc.d

ENV PYTHONUNBUFFERED=1 \
    STATE_PATH=/data/state.json \
    HEALTH_PORT=8099
