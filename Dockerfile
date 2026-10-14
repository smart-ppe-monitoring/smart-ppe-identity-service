FROM node:22-alpine AS builder

RUN apk add --no-cache libc6-compat openssl git
WORKDIR /app

RUN corepack enable && corepack prepare pnpm@latest --activate

COPY package.json pnpm-lock.yaml* ./
COPY prisma ./prisma/

RUN pnpm install --frozen-lockfile || pnpm install

COPY tsconfig.json ./
COPY src ./src/

RUN pnpm run prisma:generate
RUN pnpm run build

FROM node:22-alpine AS runner

RUN apk add --no-cache libc6-compat openssl git
WORKDIR /app

ENV NODE_ENV=production
RUN corepack enable && corepack prepare pnpm@latest --activate

COPY package.json pnpm-lock.yaml* ./
COPY prisma ./prisma/

RUN pnpm install --prod --frozen-lockfile || pnpm install --prod

COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules/@prisma ./node_modules/@prisma
COPY keys ./keys/

EXPOSE 9999

CMD ["node", "dist/server.js"]
