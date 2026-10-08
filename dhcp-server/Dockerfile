FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    g++ iproute2 iputils-ping net-tools && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY dhcp_server.cpp .
RUN g++ -Wall -O2 -o dhcp_server dhcp_server.cpp
COPY entrypoint.sh /app/
RUN chmod +x /app/entrypoint.sh
CMD ["/app/entrypoint.sh"]
