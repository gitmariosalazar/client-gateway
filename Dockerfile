#Dependencies: Node.js, npm
# Base image: Node.js 24 on Alpine Linux 3.22
FROM node:24-alpine3.22 AS deps

WORKDIR /usr/src/app

COPY package*.json ./
COPY package-lock.json ./

RUN npm install


# Build - docker build -t client-gateway .
FROM node:24-alpine3.22 AS build

WORKDIR /usr/src/app
# Copy the package files from the deps stage
COPY --from=deps /usr/src/app/node_modules ./node_modules
#Copy the rest of the application files
COPY . .

RUN npm run build
RUN npm ci --only --production && npm cache clean --force

# Create the application image
FROM node:24-alpine3.22 AS prod

WORKDIR /usr/src/app

# Copy the built application from the build stage
COPY --from=build /usr/src/app/node_modules ./node_modules
COPY --from=build /usr/src/app/dist ./dist

ENV NODE_ENV=production

USER node

EXPOSE 3000

CMD ["node", "dist/main.js"]


