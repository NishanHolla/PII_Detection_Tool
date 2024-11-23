# Use the official Node.js image as a base
FROM node:14-alpine

# Set the working directory
WORKDIR /app

# Copy package.json and package-lock.json
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy the rest of your application code
COPY . .

# Expose the port that the app runs on
EXPOSE 3000

# Command to run your Next.js app
CMD ["npm", "run", "dev"]