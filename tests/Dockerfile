FROM node:22-slim

# Playwright system deps (Chromium)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 \
    libdbus-1-3 libdrm2 libgbm1 libgtk-3-0 libxcomposite1 \
    libxdamage1 libxfixes3 libxrandr2 libxkbcommon0 libpango-1.0-0 \
    libcairo2 libasound2 libx11-xcb1 libxshmfence1 fonts-liberation \
    wget ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tests

COPY package.json .
RUN npm install && npx playwright install chromium

COPY test-e2e.js .

CMD ["node", "test-e2e.js"]
