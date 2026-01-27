# Web Demo - Rust CAS Client

本项目是一个基于 Rust `actix-web` 框架实现的 CAS (Central Authentication Service) 客户端示例。它演示了如何与 CAS Server 进行交互，实现单点登录 (SSO) 和单点登出 (SLO) 功能。

## 功能特性

- **首页保护**：访问首页时检查登录状态，未登录自动跳转到 CAS 登录页。
- **票据验证**：处理 CAS 回调，验证 Service Ticket (ST)，并解析用户信息（包含扩展属性）。
- **会话管理**：使用 Cookie Session 管理本地登录状态。
- **单点登出**：支持销毁本地会话并重定向到 CAS 登出页。

## 前提条件

1.  已部署并运行 CAS Server（参考本项目 `tai-cas-server`）。
2.  Rust 开发环境 (Cargo)。
3.  网络环境允许访问 CAS Server。

## 配置说明

在 `src/main.rs` 中，您可以找到以下配置常量，请根据实际环境进行修改：

```rust
// CAS Server 的基础地址
const CAS_SERVER_URL: &str = "http://localhost:8443/cas";

// 本应用的回调地址 (需与 CAS Server 允许的服务注册匹配)
const CLIENT_CALLBACK_URL: &str = "http://localhost:8080/callback";
```

## 运行步骤

1.  进入项目目录：

    ```bash
    cd web-demo
    ```

2.  运行项目：

    ```bash
    cargo run
    ```

3.  打开浏览器访问：
    - [http://localhost:8080](http://localhost:8080)

## 交互流程

1.  **访问首页**：用户请求 `http://localhost:8080/`。
2.  **重定向登录**：中间件/处理函数检测到未登录，重定向至 `http://localhost:8443/cas/login?service=...`。
3.  **用户认证**：用户在 CAS 页面输入凭据，认证通过后，CAS 生成 Ticket 并重定向回 `http://localhost:8080/callback?ticket=...`。
4.  **验证 Ticket**：`web-demo` 后端接收到 Ticket，向 CAS 发起 `/p3/serviceValidate` 请求验证 Ticket 有效性。
5.  **建立会话**：验证通过后，解析返回的 XML（包含用户名和属性），存入 Session，并重定向回首页。
6.  **登录成功**：首页显示用户信息。

## ODBC 数据库支持

本项目演示了如何使用 Rust 通过 ODBC 连接数据库。
API 接口：`/db-version`
返回：数据库版本信息的 JSON 数据。
配置：默认连接名为 `Kingbase_local` 的 DSN。

## 运行示例

```base
 -c http://localhost:8080/callback -s http://localhost:8443/cas -t http://localhost:8080 -d Kingbase_local -p 8080 -g postgres://postgres:'agjh^1127'@localhost/test -m mysql://root:'123'@localhost/cxgayunmas_new

  -c http://localhost:8080/callback -s http://localhost:8443/cas -t http://localhost:8080 -p 8080 -g postgres://SYSTEM:'tyjr123'@localhost:54321/TEST -m mysql://root:'123'@localhost/cxgayunmas_new -k "host=127.0.0.1 port=54321 user=SYSTEM password=tyjr123 dbname=TEST"
```
