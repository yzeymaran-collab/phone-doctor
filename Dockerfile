FROM node:18-alpine

WORKDIR /app

# Copy ALL files first (includes package.json files)
COPY . .

# Install server dependencies
WORKDIR /app/server
RUN npm install --omit=dev

# Go back to root
WORKDIR /app

# Expose port (Railway will set PORT environment variable)
EXPOSE 3000

# Start the application
CMD ["node", "server/index.js"]
