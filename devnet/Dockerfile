FROM node:20-slim

RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY contracts/ ./contracts/
COPY devnet/hardhat.config.devnet.ts ./devnet/hardhat.config.devnet.ts

RUN npx hardhat compile --config devnet/hardhat.config.devnet.ts

CMD ["npx", "hardhat", "node", "--config", "devnet/hardhat.config.devnet.ts"]
