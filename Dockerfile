FROM node:18-alpine

WORKDIR /app

# Copy ALL files first (includes package.json files)
COPY . .

# List what we have (for debugging)
RUN ls -la && ls -la server/

# Install server dependencies
RUN cd server && npm install --omit=dev && cd ..

# Expose port (Railway will set PORT environment variable)
EXPOSE 3000

# Start the application
CMD ["node", "server/index.js"]
