# ---- build ---------------------------------------------------------------
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.base.json ./
COPY packages/core/package.json packages/core/
COPY server/package.json server/
COPY web/package.json web/
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY packages/core packages/core
COPY server server
COPY web web
RUN npm run build && npm prune --omit=dev --ignore-scripts

# ---- runtime -------------------------------------------------------------
FROM node:22-alpine
ENV NODE_ENV=production \
    NODE_OPTIONS=--disable-warning=ExperimentalWarning \
    DATA_DIR=/data \
    WEB_DIR=/app/web/dist \
    PORT=8080
WORKDIR /app
COPY --from=build /app/package.json ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/packages/core/package.json ./packages/core/package.json
COPY --from=build /app/packages/core/dist ./packages/core/dist
COPY --from=build /app/server/package.json ./server/package.json
COPY --from=build /app/server/dist ./server/dist
COPY --from=build /app/web/dist ./web/dist
RUN mkdir -p /data && chown node:node /data
USER node
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:8080/v1/health || exit 1
CMD ["node", "server/dist/index.js"]
