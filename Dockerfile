# Use Ubuntu as the base image
FROM ubuntu:22.04

# Install dependencies: build tools and OpenSSL
RUN apt update && apt install -y \
    g++ \
    libssl-dev \
    make

# Set the working directory
WORKDIR /app

# Copy your C++ file into the container
COPY main.cpp .

# Build the C++ app
RUN g++ main.cpp -o wallet-test -lcrypto

# Default command to run the app
CMD ["./wallet-test"]
