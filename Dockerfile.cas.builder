# ---------------- 构建阶段 ----------------
# 使用官方最小化 Rust 镜像 (Debian Slim 基于 Bookworm)
FROM rust:1.92-slim-bookworm AS builder

# 1. 安装构建基础依赖
# pkg-config, libssl-dev: 通用编译依赖
# unixodbc-dev: odbc-api crate 编译需要 (如果需要缓存层生效，必须在这里安装)
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    gcc \
    unixodbc-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 2. 依赖缓存层
COPY cas-web-demo/Cargo.toml cas-web-demo/Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
