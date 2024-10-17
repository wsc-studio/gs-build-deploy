FROM rust:1.81-bookworm

# Include lld linker to improve build times either by using environment variable
# RUSTFLAGS="-C link-arg=-fuse-ld=lld" or with Cargo's configuration file (i.e see .cargo/config.toml).
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
   && apt-get -y install clang lld musl-tools pkg-config \
   && apt-get autoremove -y && apt-get clean -y

## Install musl toolchain
RUN rustup target add x86_64-unknown-linux-musl

## Install cargo-binstall
RUN curl -L --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash

RUN cargo binstall sqlx-cli -qy

RUN cargo install just sd mdbook mdbook-admonish


ARG version=v20.18.0
RUN apt update -y && apt install curl -y \
&& curl -fsSL https://nodejs.org/dist/$version/node-$version-linux-x64.tar.gz -o node.tar.gz \
&& tar -xzvf node.tar.gz && rm node.tar.gz \
&& echo "export PATH=$PATH:/node-$version-linux-x64/bin" >> /root/.bashrc

RUN 
# RUN sudo chown -R vscode /usr/local/cargo/