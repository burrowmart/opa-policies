# docker build -f opal/fetcher/Dockerfile -t archtenet/opal-fetcher .  (context: opa-policies/)
FROM node:20-alpine

WORKDIR /app
COPY opal/fetcher/package.json opal/fetcher/package-lock.json* ./
RUN npm install --omit=dev

COPY opal/fetcher/index.js ./

USER node
CMD ["node", "index.js"]
