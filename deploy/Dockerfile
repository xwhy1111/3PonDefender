FROM node:22-bookworm AS web-builder
WORKDIR /opt/build/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM python:3.13-slim
WORKDIR /opt/threepon
COPY server_fastapi/requirements.txt /opt/threepon/server_fastapi/requirements.txt
RUN pip install --no-cache-dir -r /opt/threepon/server_fastapi/requirements.txt \
    && useradd --system --create-home --uid 10001 threepon \
    && mkdir -p /srv/threepon/data /srv/threepon/releases \
    && chown -R threepon:threepon /srv/threepon
COPY server_fastapi /opt/threepon/server_fastapi
COPY --from=web-builder /opt/build/web/dist /opt/threepon/web/dist
USER threepon
EXPOSE 8015
ENV THREEPON_BIND=0.0.0.0:8015
ENV THREEPON_WEB_ROOT=/opt/threepon/web/dist
CMD ["sh", "-c", "uvicorn server_fastapi.main:app --host ${THREEPON_BIND%:*} --port ${THREEPON_BIND##*:} --proxy-headers"]
