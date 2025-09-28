# Stage 1: Build .NET 8 Web API
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY api/*.csproj ./
RUN dotnet restore

COPY api/ ./
RUN dotnet publish -c Release -o /out

# Stage 2: Final container with nginx + dotnet + supervisord
FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && \
    apt-get install -y nginx supervisor curl gnupg2 apt-transport-https && \
    rm -rf /var/lib/apt/lists/*

# Install .NET 8 ASP.NET Runtime
RUN curl -sSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > microsoft.gpg && \
    mv microsoft.gpg /etc/apt/trusted.gpg.d/microsoft.gpg && \
    sh -c 'echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/22.04/prod jammy main" > /etc/apt/sources.list.d/microsoft-prod.list' && \
    apt-get update && \
    apt-get install -y aspnetcore-runtime-8.0 && \
    rm -rf /var/lib/apt/lists/*

# Copy NGINX stuffs
COPY nginx/default.conf /etc/nginx/conf.d/default.conf
RUN rm /etc/nginx/sites-enabled/default
COPY nginx/index.html /usr/share/nginx/html

# Copy API stuffs
COPY --from=build /out /app

# Copy supervisord config
COPY supervisord.conf /etc/supervisord.conf

# Ports
EXPOSE 80

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
