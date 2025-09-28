FROM node:24-slim AS pnpm

RUN corepack enable
RUN corepack prepare pnpm --activate

FROM pnpm AS build
WORKDIR /app
COPY package.json pnpm-lock.yaml /app/

RUN pnpm install --frozen-lockfile
COPY . /app
RUN pnpm run build
RUN pnpm prune --prod

FROM pnpm AS dist
WORKDIR /app
COPY --from=build /app/ /app/
RUN mkdir /app/data && chown 1000:1000 /app/data
ENV FLAG="skbdg{s1mp13_pR0c_w8lk1ng_a424bdc97e2f2723}"
ENTRYPOINT ["/bin/bash"]
CMD ["/app/init.sh"]
