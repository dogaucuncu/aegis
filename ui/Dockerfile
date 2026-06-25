# Aegis SOC dashboard — Vite build, served as static files by nginx.
#   docker build -f ui/Dockerfile -t aegis-ui ./ui   (build context: ui/)
FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci || npm install
COPY . .
# The browser talks to the SOC API directly; baked in at build time.
ARG VITE_API_URL=http://localhost:8000
ENV VITE_API_URL=$VITE_API_URL
RUN npm run build

FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
