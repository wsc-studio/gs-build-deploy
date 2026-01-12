# gs-build-deploy

#### rust-red builder base（用于编译rust-red应用）
1. 使用ghcr.io的镜像，相当于内网拉取
2. 安装tokio-console用于监控tokio运行时
3. 安装lua5.4（TODO 可优化为源码安装）
4. 通过源码安装 luarocks
5. 通过源码安装 mongo-c-driver-1.27.6 (针对贯石使用的低版本mongodb server)

#### rust-red runtime base（用于运行rust-red应用）
1. 安装各种环境
2. 安装libreoffice

#### 编译 rust-red（以iot为例-shared版本）