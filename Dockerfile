FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY server/package*.json ./server/

# Install root dependencies
RUN npm ci --omit=dev

# Install server dependencies
RUN cd server && npm ci --omit=dev && cd ..

# Copy all source files
COPY . .

# Expose port (Railway will set PORT environment variable)
EXPOSE 3000

# Start the application
CMD ["node", "server/index.js"]
