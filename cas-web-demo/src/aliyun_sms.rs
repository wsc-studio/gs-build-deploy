use chrono::Utc;
use hmac::{Hmac, Mac};
use reqwest::Client;
use sha1::Sha1;
use std::collections::BTreeMap;
use url::form_urlencoded;

type HmacSha1 = Hmac<Sha1>;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct AliyunSmsClient {
    access_key_id: String,
    access_key_secret: String,
    endpoint: String,
    client: Client,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize)]
pub struct SmsSendResponse {
    #[serde(rename = "Code")]
    pub code: String,
    #[serde(rename = "Message")]
    pub message: String,
    #[serde(rename = "BizId")]
    pub biz_id: Option<String>,
    #[serde(rename = "RequestId")]
    pub request_id: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize)]
pub struct SmsCheckResponse {
    #[serde(rename = "Code")]
    pub code: String,
    #[serde(rename = "Message")]
    pub message: String,
    #[serde(rename = "BizId")]
    pub biz_id: Option<String>,
    #[serde(rename = "RequestId")]
    pub request_id: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize)]
pub struct TokenInfo {
    #[serde(rename = "AccessToken")]
    pub access_token: Option<String>,
    #[serde(rename = "JwtToken")]
    pub jwt_token: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize)]
pub struct AuthTokenResponse {
    #[serde(rename = "Code")]
    pub code: String,
    #[serde(rename = "Message")]
    pub message: String,
    #[serde(rename = "TokenInfo")]
    pub token_info: Option<TokenInfo>,
    #[serde(rename = "RequestId")]
    pub request_id: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize)]
pub struct MobileData {
    #[serde(rename = "Mobile")]
    pub mobile: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize)]
pub struct GetPhoneResponse {
    #[serde(rename = "Code")]
    pub code: String,
    #[serde(rename = "Message")]
    pub message: String,
    #[serde(rename = "Data")]
    pub data: Option<MobileData>,
    #[serde(rename = "RequestId")]
    pub request_id: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize)]
pub struct GateVerify {
    #[serde(rename = "VerifyResult")]
    pub verify_result: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize)]
pub struct VerifyPhoneResponse {
    #[serde(rename = "Code")]
    pub code: String,
    #[serde(rename = "Message")]
    pub message: String,
    #[serde(rename = "GateVerify")]
    pub gate_verify: Option<GateVerify>,
    #[serde(rename = "RequestId")]
    pub request_id: Option<String>,
}

impl AliyunSmsClient {
    pub fn new(access_key_id: &str, access_key_secret: &str) -> Self {
        Self {
            access_key_id: access_key_id.to_string(),
            access_key_secret: access_key_secret.to_string(),
            // 切换为号码认证服务 Endpoint
            endpoint: "https://dypnsapi.aliyuncs.com".to_string(),
            client: Client::new(),
        }
    }

    async fn do_request<T: DeserializeOwned>(
        &self,
        action: &str,
        business_params: BTreeMap<&str, &str>,
    ) -> Result<T, Box<dyn std::error::Error>> {
        let mut params = BTreeMap::new();
        // 系统参数
        params.insert("AccessKeyId", self.access_key_id.as_str());
        params.insert("Format", "JSON");
        params.insert("SignatureMethod", "HMAC-SHA1");
        params.insert("SignatureVersion", "1.0");
        params.insert("Version", "2017-05-25");
        let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        params.insert("Timestamp", &timestamp);
        let nonce = uuid::Uuid::new_v4().to_string();
        params.insert("SignatureNonce", &nonce);

        // 业务参数
        params.insert("Action", action);
        for (k, v) in business_params {
            params.insert(k, v);
        }

        // 计算签名
        let signature = self.sign(&params);

        // 发送请求
        let mut final_params = params.clone();
        final_params.insert("Signature", &signature);

        let mut query_string = form_urlencoded::Serializer::new(String::new());
        for (k, v) in &final_params {
            query_string.append_pair(k, v);
        }
        let full_query = query_string.finish();
        let full_url = format!("{}?{}", self.endpoint, full_query);

        let resp = self
            .client
            .post(&full_url)
            .send()
            .await?
            .json::<T>()
            .await?;

        Ok(resp)
    }

    /// 发送短信验证码 (SendSmsVerifyCode)
    pub async fn send_sms_verify_code(
        &self,
        phone_number: &str,
        sign_name: &str,
        template_code: &str,
        template_param: &str,
    ) -> Result<SmsSendResponse, Box<dyn std::error::Error>> {
        let mut params = BTreeMap::new();
        params.insert("PhoneNumber", phone_number);
        params.insert("SignName", sign_name);
        params.insert("TemplateCode", template_code);
        params.insert("TemplateParam", template_param);

        self.do_request("SendSmsVerifyCode", params).await
    }

    /// 核验短信验证码 (CheckSmsVerifyCode)
    pub async fn check_sms_verify_code(
        &self,
        phone_number: &str,
        verify_code: &str,
    ) -> Result<SmsCheckResponse, Box<dyn std::error::Error>> {
        let mut params = BTreeMap::new();
        params.insert("PhoneNumber", phone_number);
        params.insert("VerifyCode", verify_code);

        self.do_request("CheckSmsVerifyCode", params).await
    }

    /// 获取 H5 认证授权 Token (GetAuthToken)
    pub async fn get_auth_token(
        &self,
        scene_code: &str,
        origin_url: &str,
    ) -> Result<AuthTokenResponse, Box<dyn std::error::Error>> {
        let mut params = BTreeMap::new();
        params.insert("SceneCode", scene_code);
        params.insert("OriginUrl", origin_url);

        self.do_request("GetAuthToken", params).await
    }

    /// 一键登录取号 (GetPhoneWithToken)
    pub async fn get_phone_with_token(
        &self,
        sp_token: &str,
    ) -> Result<GetPhoneResponse, Box<dyn std::error::Error>> {
        let mut params = BTreeMap::new();
        params.insert("SpToken", sp_token);

        self.do_request("GetPhoneWithToken", params).await
    }

    /// 本机号码校验 (VerifyPhoneWithToken)
    pub async fn verify_phone_with_token(
        &self,
        sp_token: &str,
        phone_number: &str,
    ) -> Result<VerifyPhoneResponse, Box<dyn std::error::Error>> {
        let mut params = BTreeMap::new();
        params.insert("SpToken", sp_token);
        params.insert("PhoneNumber", phone_number);

        self.do_request("VerifyPhoneWithToken", params).await
    }

    fn sign(&self, params: &BTreeMap<&str, &str>) -> String {
        // 1. 构造规范化查询字符串 (CanonicalizedQueryString)
        let mut query_string = form_urlencoded::Serializer::new(String::new());
        for (k, v) in params {
            query_string.append_pair(k, v);
        }
        let canonicalized_query_string = query_string.finish();

        // 2. 构造签名字符串 (StringToSign)
        // StringToSign = HTTPMethod + "&" + percentEncode("/") + "&" + percentEncode(CanonicalizedQueryString)
        let string_to_sign = format!(
            "POST&{}&{}",
            percent_encode("/"),
            percent_encode(&canonicalized_query_string)
        );

        // 3. 计算 HMAC-SHA1
        let key = format!("{}&", self.access_key_secret);
        let mut mac =
            HmacSha1::new_from_slice(key.as_bytes()).expect("HMAC can take key of any size");
        mac.update(string_to_sign.as_bytes());
        let result = mac.finalize();
        let code_bytes = result.into_bytes();

        // 4. Base64 编码
        use base64::{Engine as _, engine::general_purpose};
        general_purpose::STANDARD.encode(code_bytes)
    }
}

// 阿里云特殊的 URL 编码规则
fn percent_encode(s: &str) -> String {
    use url::form_urlencoded::byte_serialize;
    let encoded: String = byte_serialize(s.as_bytes()).collect();
    encoded
        .replace('+', "%20")
        .replace('*', "%2A")
        .replace("%7E", "~")
}
