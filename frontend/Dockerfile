FROM node:24-alpine AS build
WORKDIR /app
ARG VITE_GRAFANA_URL=http://127.0.0.1:3000
ENV VITE_GRAFANA_URL=$VITE_GRAFANA_URL
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:1.29-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=5 CMD wget -q --spider http://127.0.0.1/ || exit 1
