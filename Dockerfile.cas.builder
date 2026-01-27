# ---------------- 构建阶段 ----------------
# 使用 CentOS 7.6 作为构建环境，确保编译产物兼容老版本 GLIBC
FROM centos:7.6.1810 AS builder

# 1. 替换阿里云镜像源 (CentOS 7 已 EOL，必须换源)
RUN curl -o /etc/yum.repos.d/CentOS-Base.repo https://mirrors.aliyun.com/repo/Centos-7.repo && \
    sed -i -e '/mirrors.cloud.aliyuncs.com/d' -e '/mirrors.aliyuncs.com/d' /etc/yum.repos.d/CentOS-Base.repo && \
    yum makecache
# 2. 安装构建依赖 (gcc, linker, unixODBC-devel)
# RUN yum install -y gcc unixODBC-devel
RUN yum groupinstall -y "Development Tools" && \
    yum install -y wget tar gzip openssl-devel && \
    cd /tmp && \
    wget https://www.unixodbc.org/unixODBC-2.3.14.tar.gz && \
    tar -zxf unixODBC-2.3.14.tar.gz && \
    cd unixODBC-2.3.14 && \
    ./configure --prefix=/mnt/odbc-here --disable-gui --disable-drivers CFLAGS="-std=gnu99" && \
    make && \
    make install 

# /mnt/odbc/here bin/lib/etc 目录下的文件需要复制到运行时环境
# 运行时环境需要安装 unixODBC 管理器，以及具体的数据库驱动 (如 Kingbase ODBC Driver)

# 3. 安装 Rust 环境
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# 指定 unixODBC 的头文件和库文件路径，供编译时使用
ENV C_INCLUDE_PATH=/mnt/odbc-here/include
ENV LIBRARY_PATH=/mnt/odbc-here/lib
ENV LD_LIBRARY_PATH=/mnt/odbc-here/lib
ENV PKG_CONFIG_PATH=/mnt/odbc-here/lib/pkgconfig

WORKDIR /app

# 4. 依赖缓存层
COPY cas-web-demo/Cargo.toml cas-web-demo/Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
# 在 CentOS 环境下默认编译为 gnu target，兼容性最好
RUN cargo build --release
