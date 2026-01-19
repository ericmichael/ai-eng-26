FROM --platform=i386 docker.io/i386/debian:buster
ARG DEBIAN_FRONTEND=noninteractive

# Use archived repos (buster is EOL)
RUN sed -i 's|http://deb.debian.org/debian|http://archive.debian.org/debian|g' /etc/apt/sources.list && \
    sed -i 's|http://deb.debian.org/debian-security|http://archive.debian.org/debian-security|g' /etc/apt/sources.list && \
    sed -i '/buster-updates/d' /etc/apt/sources.list

# System packages (minimal)
RUN apt-get update && apt-get -y upgrade && apt-get -y install --no-install-recommends \
    # Session
    tmux \
    # Editor
    vim-tiny \
    # Version control
    git \
    # Python
    python3 \
    python3-pip \
    python3-venv \
    # Networking
    curl \
    # File utilities
    tree \
    jq \
    ripgrep \
    less \
    file \
    zip \
    unzip \
    findutils \
    coreutils \
    # Process management
    procps \
    # Database
    sqlite3 \
    # Text processing
    sed \
    gawk \
    diffutils \
    patch \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Python testing & dev tools (minimal)
RUN pip3 install --no-cache-dir \
    pytest \
    pytest-timeout \
    flake8 \
    pyyaml

# Create user with uid 1000 (matches CheerpX default)
RUN useradd -m -u 1000 -s /bin/bash user && \
    mkdir -p /home/user/repos /home/user/workspace && \
    chown -R user:user /home/user

# Set working directory
WORKDIR /home/user
