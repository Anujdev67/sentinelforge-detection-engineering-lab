FROM node:24-alpine@sha256:d32cdf619f63fe0471182d08996dd516c6275bb5fd31ae06e55a570bd9e1ad43 AS build

WORKDIR /app
RUN corepack enable
COPY apps/dashboard/package.json apps/dashboard/pnpm-lock.yaml apps/dashboard/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY apps/dashboard/ ./
RUN pnpm build

FROM nginxinc/nginx-unprivileged:1.31-alpine3.24@sha256:334d92979f15aaecd5dd50af5105e1230e2bb70765d45b1e2f964e7c5eda81c3 AS runtime
COPY apps/dashboard/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 8080
HEALTHCHECK --interval=20s --timeout=5s --start-period=10s --retries=5 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1
