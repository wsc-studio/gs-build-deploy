use actix_session::{Session, SessionMiddleware, storage::CookieSessionStore};
use actix_web::{
    App, HttpResponse, HttpServer, Responder, cookie::Key, get, http::header, post, web,
};
use bb8::{ManageConnection, Pool};
use bb8_postgres::PostgresConnectionManager;
use clap::Parser;
use odbc_api::{Connection, ConnectionOptions, Cursor, Environment};
use once_cell::sync::Lazy;
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{MySqlPool, PgPool, Row};
use std::sync::{Arc, Mutex};
use tokio_postgres::NoTls;

mod aliyun_sms;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[arg(short, long, default_value_t = 8080, env = "PORT")]
    pub port: u16,
    #[arg(short = 's', long, env = "CAS_SERVER_URL")]
    pub cas_server_url: String,
    #[arg(short, long, env = "CLIENT_CALLBACK_URL")]
    pub client_callback_url: String,
    #[arg(short, long, env = "THIS_HOME_URL")]
    pub this_home_url: String,
    // 容器 docker run -e ENABLE_CONSOLE=true
    #[arg(long, short, env = "DSN")]
    pub dsn: Option<String>,
    #[arg(short, long, env = "MYSQL_URL")]
    pub mysql_url: Option<String>,
    #[arg(short = 'g', long, env = "POSTGRES_URL")]
    pub postgresql_url: Option<String>,
    #[arg(short = 'k', long, env = "KINGBASE_URL")]
    pub kingbase_url: Option<String>,

    // 阿里云短信配置
    #[arg(long, env = "ALIYUN_ACCESS_KEY_ID")]
    pub aliyun_access_key_id: Option<String>,
    #[arg(long, env = "ALIYUN_ACCESS_KEY_SECRET")]
    pub aliyun_access_key_secret: Option<String>,
    #[arg(long, env = "ALIYUN_SMS_SIGN_NAME", default_value = "速通互联验证码")]
    pub aliyun_sms_sign_name: String,
    #[arg(long, env = "ALIYUN_SMS_TEMPLATE_CODE", default_value = "100001")]
    pub aliyun_sms_template_code: String,
    #[arg(long, env = "ALIYUN_SMS_SCENE_CODE", default_value = "")]
    pub aliyun_sms_scene_code: String,
}

// --- 配置常量 ---

// 全局 ODBC 环境
static ODBC_ENV: Lazy<Environment> =
    Lazy::new(|| Environment::new().expect("Failed to create ODBC Environment"));

// 异步 ODBC 连接包装器
pub struct AsyncOdbcConnection {
    inner: Arc<Mutex<Connection<'static>>>,
}

impl AsyncOdbcConnection {
    pub async fn query_version(&self) -> Result<String, String> {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            let conn = inner.lock().map_err(|e| e.to_string())?;
            match conn
                .execute("SELECT version()", (), None)
                .map_err(|e| e.to_string())?
            {
                Some(mut cursor) => {
                    if let Some(mut row) = cursor.next_row().map_err(|e| e.to_string())? {
                        let mut buf = Vec::new();
                        // ODBC 列索引从 1 开始
                        row.get_text(1, &mut buf).map_err(|e| e.to_string())?;
                        return Ok(String::from_utf8_lossy(&buf).to_string());
                    }
                    Ok("No data found".to_string())
                }
                None => Ok("No cursor returned".to_string()),
            }
        })
        .await
        .map_err(|e| e.to_string())?
    }
}

#[derive(Clone)]
pub struct OdbcConnectionManager {
    connection_string: String,
}

impl OdbcConnectionManager {
    pub fn new(connection_string: &str) -> Self {
        Self {
            connection_string: connection_string.to_string(),
        }
    }
}

impl ManageConnection for OdbcConnectionManager {
    type Connection = AsyncOdbcConnection;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    async fn connect(&self) -> Result<Self::Connection, Self::Error> {
        let connection_string = self.connection_string.clone();

        let connection = tokio::task::spawn_blocking(move || {
            ODBC_ENV
                .connect_with_connection_string(&connection_string, ConnectionOptions::default())
        })
        .await
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

        Ok(AsyncOdbcConnection {
            inner: Arc::new(Mutex::new(connection)),
        })
    }

    async fn is_valid(&self, _conn: &mut Self::Connection) -> Result<(), Self::Error> {
        Ok(())
    }

    fn has_broken(&self, _conn: &mut Self::Connection) -> bool {
        false
    }
}

type DbPool = Pool<OdbcConnectionManager>;

#[derive(Clone)]
struct SmsConfig {
    sign_name: String,
    template_code: String,
    scene_code: String,
}

#[derive(Clone)]
struct AppState {
    odbc_pool: Option<DbPool>,
    mysql_pool: Option<MySqlPool>,
    pg_pool: Option<PgPool>,
    kingbase_pool: Option<bb8::Pool<PostgresConnectionManager<NoTls>>>,
    sms_client: Option<aliyun_sms::AliyunSmsClient>,
    sms_config: SmsConfig,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    // 解析命令行参数
    let args = Args::parse();
    println!("args: [{:?}]", &args);

    // 生成一个随机密钥用于 Session 加密 (生产环境请固定)
    let secret_key = Key::generate();

    // 初始化 bb8 连接池
    let odbc_pool = match args.dsn.as_deref() {
        Some(dsn) => {
            println!("Using DSN: {}", dsn);
            let pool = Pool::builder()
                .max_size(10)
                .build(OdbcConnectionManager::new(format!("DSN={};", dsn).as_str()))
                .await
                .expect("Failed to create connection pool");
            Some(pool)
        }
        None => {
            println!("Using default DSN: None;");
            None
        }
    };

    // 初始化 MySQL 连接池
    let mysql_pool = match args.mysql_url.as_deref() {
        Some(url) => {
            println!("Using MySQL: {}", url);
            let pool = MySqlPool::connect(url)
                .await
                .expect("Failed to create MySQL pool");
            Some(pool)
        }
        None => None,
    };

    // 初始化 PostgreSQL 连接池
    let pg_pool = match args.postgresql_url.as_deref() {
        Some(url) => {
            println!("Using PostgreSQL: {}", url);
            let pool = PgPool::connect(url)
                .await
                .expect("Failed to create PostgreSQL pool");
            Some(pool)
        }
        None => None,
    };

    // 初始化 Kingbase 连接池
    let kingbase_pool = match args.kingbase_url.as_deref() {
        Some(url) => {
            println!("Using Kingbase: {}", url);
            let mgr = PostgresConnectionManager::new_from_stringlike(url, NoTls)
                .expect("Failed to create Kingbase connection manager");
            let pool: bb8::Pool<PostgresConnectionManager<NoTls>> = Pool::builder()
                .max_size(16)
                .build(mgr)
                .await
                .expect("Failed to create Kingbase pool");
            Some(pool)
        }
        None => None,
    };

    // 初始化阿里云短信客户端
    let sms_client = if let (Some(ak), Some(sk)) = (
        args.aliyun_access_key_id.as_deref(),
        args.aliyun_access_key_secret.as_deref(),
    ) {
        println!("Using Aliyun SMS");
        Some(aliyun_sms::AliyunSmsClient::new(ak, sk))
    } else {
        println!("Aliyun SMS not configured");
        None
    };

    let sms_config = SmsConfig {
        sign_name: args.aliyun_sms_sign_name.clone(),
        template_code: args.aliyun_sms_template_code.clone(),
        scene_code: args.aliyun_sms_scene_code.clone(),
    };

    let app_state = web::Data::new(AppState {
        odbc_pool,
        mysql_pool,
        pg_pool,
        kingbase_pool,
        sms_client,
        sms_config,
    });

    let port = args.port;
    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .app_data(web::Data::new(args.clone()))
            // 启用 Session 中间件
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                secret_key.clone(),
            ))
            .service(index)
            .service(login)
            .service(logout)
            .service(cas_callback)
            .service(db_version)
            .service(mysql_version)
            .service(pg_version)
            .service(kingbase_version)
            .service(send_sms_code)
            .service(verify_sms_code)
            .service(get_auth_token_handler)
            .service(get_phone_with_token_handler)
            .service(verify_phone_with_token_handler)
    })
    .bind(("0.0.0.0", port))?
    .run()
    .await
}

// --- API Endpoints ---

#[derive(Deserialize)]
struct SendSmsParams {
    phone: String,
}

// 发送短信验证码
#[post("/sms/send")]
async fn send_sms_code(
    data: web::Data<AppState>,
    params: web::Json<SendSmsParams>,
) -> impl Responder {
    if let Some(client) = &data.sms_client {
        // 使用配置的签名和模板
        let sign_name = &data.sms_config.sign_name;
        let template_code = &data.sms_config.template_code;
        // 使用 ##code## 让阿里云自动生成验证码
        let template_param = "{\"code\":\"##code##\"}";

        match client
            .send_sms_verify_code(&params.phone, sign_name, template_code, template_param)
            .await
        {
            Ok(resp) => {
                if resp.code == "OK" {
                    HttpResponse::Ok().json(json!({ "status": "success", "message": "发送成功", "biz_id": resp.biz_id }))
                } else {
                    HttpResponse::BadRequest().json(
                        json!({ "status": "error", "message": resp.message, "code": resp.code }),
                    )
                }
            }
            Err(e) => HttpResponse::InternalServerError().body(format!("Sms error: {}", e)),
        }
    } else {
        HttpResponse::ServiceUnavailable()
            .json(json!({ "status": "error", "message": "SMS client not configured" }))
    }
}

#[derive(Deserialize)]
struct VerifySmsParams {
    phone: String,
    code: String,
}

// 校验短信验证码
#[post("/sms/verify")]
async fn verify_sms_code(
    data: web::Data<AppState>,
    params: web::Json<VerifySmsParams>,
) -> impl Responder {
    if let Some(client) = &data.sms_client {
        match client
            .check_sms_verify_code(&params.phone, &params.code)
            .await
        {
            Ok(resp) => {
                if resp.code == "OK" {
                    HttpResponse::Ok().json(json!({ "status": "success", "message": "验证通过" }))
                } else {
                    HttpResponse::BadRequest().json(
                        json!({ "status": "error", "message": resp.message, "code": resp.code }),
                    )
                }
            }
            Err(e) => HttpResponse::InternalServerError().body(format!("Sms error: {}", e)),
        }
    } else {
        HttpResponse::ServiceUnavailable()
            .json(json!({ "status": "error", "message": "SMS client not configured" }))
    }
}

#[derive(Deserialize)]
struct AuthTokenParams {
    origin_url: Option<String>,
}

// 获取 H5 认证授权 Token
#[post("/auth/token")]
async fn get_auth_token_handler(
    data: web::Data<AppState>,
    params: web::Json<AuthTokenParams>,
) -> impl Responder {
    if let Some(client) = &data.sms_client {
        let scene_code = &data.sms_config.scene_code;
        let origin_url = params.origin_url.as_deref().unwrap_or("");

        match client.get_auth_token(scene_code, origin_url).await {
            Ok(resp) => {
                if resp.code == "OK" {
                    HttpResponse::Ok()
                        .json(json!({ "status": "success", "token_info": resp.token_info }))
                } else {
                    HttpResponse::BadRequest().json(
                        json!({ "status": "error", "message": resp.message, "code": resp.code }),
                    )
                }
            }
            Err(e) => HttpResponse::InternalServerError().body(format!("Auth error: {}", e)),
        }
    } else {
        HttpResponse::ServiceUnavailable()
            .json(json!({ "status": "error", "message": "SMS client not configured" }))
    }
}

#[derive(Deserialize)]
struct GetPhoneParams {
    sp_token: String,
}

// 一键登录取号
#[post("/auth/phone")]
async fn get_phone_with_token_handler(
    data: web::Data<AppState>,
    params: web::Json<GetPhoneParams>,
) -> impl Responder {
    if let Some(client) = &data.sms_client {
        match client.get_phone_with_token(&params.sp_token).await {
            Ok(resp) => {
                if resp.code == "OK" {
                    HttpResponse::Ok().json(json!({ "status": "success", "data": resp.data }))
                } else {
                    HttpResponse::BadRequest().json(
                        json!({ "status": "error", "message": resp.message, "code": resp.code }),
                    )
                }
            }
            Err(e) => HttpResponse::InternalServerError().body(format!("Auth error: {}", e)),
        }
    } else {
        HttpResponse::ServiceUnavailable()
            .json(json!({ "status": "error", "message": "SMS client not configured" }))
    }
}

#[derive(Deserialize)]
struct VerifyPhoneParams {
    sp_token: String,
    phone_number: String,
}

// 本机号码校验
#[post("/auth/verify")]
async fn verify_phone_with_token_handler(
    data: web::Data<AppState>,
    params: web::Json<VerifyPhoneParams>,
) -> impl Responder {
    if let Some(client) = &data.sms_client {
        match client
            .verify_phone_with_token(&params.sp_token, &params.phone_number)
            .await
        {
            Ok(resp) => {
                if resp.code == "OK" {
                    HttpResponse::Ok()
                        .json(json!({ "status": "success", "gate_verify": resp.gate_verify }))
                } else {
                    HttpResponse::BadRequest().json(
                        json!({ "status": "error", "message": resp.message, "code": resp.code }),
                    )
                }
            }
            Err(e) => HttpResponse::InternalServerError().body(format!("Auth error: {}", e)),
        }
    } else {
        HttpResponse::ServiceUnavailable()
            .json(json!({ "status": "error", "message": "SMS client not configured" }))
    }
}

// 5. ODBC 数据库查询示例
#[get("/db-version")]
async fn db_version(data: web::Data<AppState>) -> impl Responder {
    if let Some(pool) = &data.odbc_pool {
        let result = async {
            let conn = pool.get().await.map_err(|e| match e {
                bb8::RunError::User(err) => err.to_string(),
                bb8::RunError::TimedOut => "Connection timed out".to_string(),
            })?;
            conn.query_version().await
        }
        .await;
        match result {
            Ok(version) => HttpResponse::Ok().json(json!({ "version": version })),
            Err(e) => HttpResponse::InternalServerError().body(format!("Database error: {}", e)),
        }
    } else {
        HttpResponse::InternalServerError().body("ODBC pool not initialized")
    }
}

// 6. MySQL 数据库查询示例
#[get("/mysql-version")]
async fn mysql_version(data: web::Data<AppState>) -> impl Responder {
    if let Some(pool) = &data.mysql_pool {
        let result = sqlx::query("SELECT VERSION()").fetch_one(pool).await;

        match result {
            Ok(row) => {
                let version: String = row.get(0);
                HttpResponse::Ok().json(json!({ "version": version }))
            }
            Err(e) => HttpResponse::InternalServerError().body(format!("MySQL error: {}", e)),
        }
    } else {
        HttpResponse::InternalServerError().body("MySQL pool not initialized")
    }
}

// 7. PostgreSQL 数据库查询示例
#[get("/pg-version")]
async fn pg_version(data: web::Data<AppState>) -> impl Responder {
    if let Some(pool) = &data.pg_pool {
        let result = sqlx::query("SELECT version()").fetch_one(pool).await;

        match result {
            Ok(row) => {
                let version: String = row.get(0);
                HttpResponse::Ok().json(json!({ "version": version }))
            }
            Err(e) => HttpResponse::InternalServerError().body(format!("PostgreSQL error: {}", e)),
        }
    } else {
        HttpResponse::InternalServerError().body("PostgreSQL pool not initialized")
    }
}

// 8. Kingbase 数据库查询示例
#[get("/kingbase-version")]
async fn kingbase_version(data: web::Data<AppState>) -> impl Responder {
    if let Some(pool) = &data.kingbase_pool {
        match pool.get().await {
            Ok(client) => match client.query_one("SELECT version(), now()::text", &[]).await {
                Ok(row) => {
                    let version: String = row.get(0);
                    let now: String = row.get(1);
                    println!("version: {}", version);
                    println!("now: {}", now);
                    HttpResponse::Ok().json(json!({ "version": version, "now": now }))
                }
                Err(e) => {
                    HttpResponse::InternalServerError().body(format!("Kingbase error: {}", e))
                }
            },
            Err(e) => HttpResponse::InternalServerError().body(format!("Kingbase error: {}", e)),
        }
    } else {
        HttpResponse::InternalServerError().body("Kingbase pool not initialized")
    }
}

// 1. 首页 (受保护资源)
#[get("/")]
async fn index(session: Session) -> impl Responder {
    // 检查 Session 中是否有用户信息
    if let Ok(Some(user)) = session.get::<CasUser>("user") {
        let mut html = format!("<h1>欢迎回来, {}!</h1>", user.username);
        html.push_str("<h3>用户属性:</h3><ul>");
        for (k, v) in user.attributes {
            html.push_str(&format!("<li><b>{}:</b> {}</li>", k, v));
        }
        html.push_str("</ul><br/><a href='/logout'>退出登录</a>");
        HttpResponse::Ok().body(html)
    } else {
        // 未登录，重定向到本地登录处理
        HttpResponse::Found()
            .append_header((header::LOCATION, "/login"))
            .finish()
    }
}

// 2. 登录处理 (重定向到 CAS)
#[get("/login")]
async fn login(args: web::Data<Args>) -> impl Responder {
    // 构造 CAS 登录 URL，并附带 service 参数
    let cas_login_url = format!(
        "{}/login?service={}",
        args.cas_server_url, args.client_callback_url
    );
    HttpResponse::Found()
        .append_header((header::LOCATION, cas_login_url))
        .finish()
}

// 3. CAS 回调处理 (Ticket 验证)
#[derive(Deserialize)]
struct CasCallbackParams {
    ticket: String,
}

#[get("/callback")]
async fn cas_callback(
    session: Session,
    params: web::Query<CasCallbackParams>,
    args: web::Data<Args>,
) -> impl Responder {
    let ticket = &params.ticket;

    // 向 CAS Server 发起后端验证请求
    // URL: /p3/serviceValidate (CAS 3.0 协议)
    let validate_url = format!(
        "{}/p3/serviceValidate?service={}&ticket={}",
        args.cas_server_url, args.client_callback_url, ticket
    );

    // 发起 HTTP 请求 (这里使用 blocking client 简化，actix 中建议用 reqwest::Client 的 async 方法)
    let response = match Client::new().get(&validate_url).send().await {
        Ok(res) => res.text().await.unwrap_or_default(),
        Err(_) => return HttpResponse::InternalServerError().body("无法连接到 CAS 服务器"),
    };

    // 解析 CAS 返回的 XML
    match parse_cas_response(&response) {
        Ok(user) => {
            // 将用户信息存入 Session
            let _ = session.insert("user", user);

            // 登录成功，重定向回首页
            HttpResponse::Found()
                .append_header((header::LOCATION, "/"))
                .finish()
        }
        Err(e) => HttpResponse::Unauthorized().body(format!("CAS 验证失败: {}", e)),
    }
}

// 4. 登出处理
#[get("/logout")]
async fn logout(session: Session, args: web::Data<Args>) -> impl Responder {
    // 清除本地 Session
    session.purge();

    // 重定向到 CAS 登出页
    let cas_logout_url = format!(
        "{}/logout?service={}",
        args.cas_server_url, args.this_home_url
    );
    HttpResponse::Found()
        .append_header((header::LOCATION, cas_logout_url))
        .finish()
}

use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize)]
struct CasUser {
    username: String,
    attributes: HashMap<String, String>,
}

// 辅助函数：使用 quick-xml 解析 CAS 响应
fn parse_cas_response(xml: &str) -> Result<CasUser, String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut username = String::new();
    let mut attributes = HashMap::new();

    let mut in_success = false;
    let mut in_attributes = false;
    let mut current_tag = String::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                let tag_name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();

                if tag_name == "authenticationSuccess" {
                    in_success = true;
                } else if tag_name == "attributes" {
                    in_attributes = true;
                }

                current_tag = tag_name;
            }
            Ok(Event::End(ref e)) => {
                let tag_name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                if tag_name == "attributes" {
                    in_attributes = false;
                }
                current_tag.clear();
            }
            Ok(Event::Text(e)) => {
                if in_success {
                    // 手动处理 XML 转义，规避 quick-xml 版本兼容性问题
                    let raw_text = String::from_utf8_lossy(e.as_ref()).to_string();
                    let text = raw_text
                        .replace("&amp;", "&")
                        .replace("&lt;", "<")
                        .replace("&gt;", ">")
                        .replace("&quot;", "\"")
                        .replace("&apos;", "'");

                    if current_tag == "user" {
                        username = text;
                    } else if in_attributes && !current_tag.is_empty() {
                        attributes.insert(current_tag.clone(), text);
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("XML 解析错误: {:?}", e)),
            _ => (),
        }
    }

    if username.is_empty() {
        return Err("未找到用户名或认证失败".to_string());
    }

    Ok(CasUser {
        username,
        attributes,
    })
}
