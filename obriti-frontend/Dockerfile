# Stage 1: Build the app
FROM node:20-alpine AS builder

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

# Stage 2: Serve with nginx
FROM nginx:alpine

# Remove default nginx static assets
RUN rm -rf /usr/share/nginx/html/*

# Copy built assets from builder
COPY --from=builder /app/dist /usr/share/nginx/html

# Create directory for SSL certificates
RUN mkdir -p /etc/nginx/certs

# Copy SSL certificates
COPY cert/fareportal-2025.pem /etc/nginx/certs/
COPY cert/fareportal-2025.key /etc/nginx/certs/

# Copy nginx SSL configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Set proper permissions for certificates
RUN chmod 644 /etc/nginx/certs/fareportal-2025.pem
RUN chmod 600 /etc/nginx/certs/fareportal-2025.key

# Expose both HTTP (for redirect) and HTTPS ports
EXPOSE 80 443

CMD ["nginx", "-g", "daemon off;"] 
