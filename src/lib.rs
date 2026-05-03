use worker::*;
use serde::{Deserialize, Serialize};
use worker::wasm_bindgen::JsValue;

// ─── Data Types ──────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct Message {
    id: i64,
    name: String,
    email: Option<String>,
    content: String,
    attachment_key: Option<String>,
    #[serde(deserialize_with = "bool_from_int_or_bool")]
    approved: bool,
    created_at: String,
}

#[derive(Debug, Deserialize)]
struct NewMessage {
    name: String,
    email: Option<String>,
    content: String,
    attachment_key: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct ApiResponse<T: Serialize> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

// ─── Custom Deserializer ──────────────────────────────────────────────────────

/// Accepts both JSON booleans and integers (0/1) for SQLite INTEGER columns.
fn bool_from_int_or_bool<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<bool, D::Error> {
    use serde::de::{self, Visitor};

    struct BoolOrInt;

    impl<'de> Visitor<'de> for BoolOrInt {
        type Value = bool;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("bool or integer")
        }
        fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<bool, E> {
            Ok(v)
        }
        fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<bool, E> {
            Ok(v != 0)
        }
        fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<bool, E> {
            Ok(v != 0)
        }
    }

    d.deserialize_any(BoolOrInt)
}

// ─── Response Helpers ─────────────────────────────────────────────────────────

fn ok_response<T: Serialize>(data: T) -> Result<Response> {
    Response::from_json(&ApiResponse {
        success: true,
        data: Some(data),
        error: None::<String>,
    })
}

fn err_response(message: &str, status: u16) -> Result<Response> {
    let resp = Response::from_json(&ApiResponse::<()> {
        success: false,
        data: None,
        error: Some(message.to_string()),
    })?;
    Ok(resp.with_status(status))
}

// ─── JWT Utilities ────────────────────────────────────────────────────────────

fn create_jwt(username: &str, secret: &str) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let now = Date::now().as_millis() / 1000;
    let exp = now + 86400u64; // 24 hours

    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    // Use serde_json to guarantee proper JSON escaping of the username.
    let payload_json = serde_json::json!({"sub": username, "iat": now, "exp": exp}).to_string();
    let payload = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());

    let signing_input = format!("{}.{}", header, payload);

    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key size");
    mac.update(signing_input.as_bytes());
    let sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());

    format!("{}.{}", signing_input, sig)
}

fn verify_jwt(token: &str, secret: &str) -> Option<String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut parts = token.splitn(3, '.');
    let header_b64 = parts.next()?;
    let payload_b64 = parts.next()?;
    let sig_b64 = parts.next()?;

    // Decode the provided signature bytes.
    let sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64).ok()?;

    // verify_slice internally uses constant-time comparison (via subtle).
    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key size");
    mac.update(signing_input.as_bytes());
    mac.verify_slice(&sig_bytes).ok()?;

    // Decode and validate payload
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).ok()?;

    let exp = payload["exp"].as_u64()?;
    if Date::now().as_millis() / 1000 > exp {
        return None; // Expired
    }

    payload["sub"].as_str().map(|s| s.to_string())
}

async fn check_auth(req: &Request, env: &Env) -> Result<Option<String>> {
    let auth_opt = req.headers().get("Authorization")?;
    let token = match auth_opt {
        Some(ref h) if h.starts_with("Bearer ") => h[7..].to_string(),
        _ => return Ok(None),
    };
    let secret = env.secret("JWT_SECRET")?.to_string();
    Ok(verify_jwt(&token, &secret))
}

// ─── Misc Helpers ─────────────────────────────────────────────────────────────

/// Sanitise a filename to be safe for use as an object-storage key segment.
///
/// Only alphanumeric characters, `.`, `-`, and `_` are retained.  If the
/// result is empty after filtering, the fallback value `"file"` is returned.
fn sanitize_filename(filename: &str) -> String {
    let s: String = filename
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '.' || *c == '-' || *c == '_')
        .collect();
    if s.is_empty() { "file".to_string() } else { s }
}

fn generate_attachment_key(filename: &str) -> Result<String> {
    let mut bytes = [0u8; 8];
    getrandom::getrandom(&mut bytes)
        .map_err(|e| Error::RustError(format!("Failed to generate random bytes: {}", e)))?;
    let ts = Date::now().as_millis();
    let safe_name = sanitize_filename(filename);
    Ok(format!("{}-{}/{}", ts, hex::encode(bytes), safe_name))
}

// ─── Main Event Handler ───────────────────────────────────────────────────────

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    // Handle CORS preflight
    if req.method() == Method::Options {
        let h = Headers::new();
        h.set("Access-Control-Allow-Origin", "*")?;
        h.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")?;
        h.set("Access-Control-Allow-Headers", "Content-Type, Authorization")?;
        return Ok(Response::empty()?.with_headers(h));
    }

    let url = req.url()?;
    let path = url.path();

    let mut response = handle_request(req, &env, path).await?;

    // Attach CORS header to every response
    response.headers_mut().set("Access-Control-Allow-Origin", "*")?;

    Ok(response)
}

// ─── Router ───────────────────────────────────────────────────────────────────

async fn handle_request(mut req: Request, env: &Env, path: &str) -> Result<Response> {
    let method = req.method();

    match (method.clone(), path) {
        // ── Static pages ──
        (Method::Get, "/") | (Method::Get, "/index.html") => {
            Response::from_html(include_str!("../static/index.html"))
        }
        (Method::Get, "/admin") | (Method::Get, "/admin/") => {
            Response::from_html(include_str!("../static/admin.html"))
        }

        // ── Public API ──
        (Method::Get, "/api/messages") => api_get_messages(env).await,
        (Method::Post, "/api/messages") => api_create_message(&mut req, env).await,
        (Method::Post, "/api/upload") => api_upload_attachment(&mut req, env).await,

        // ── Attachment retrieval ──
        (Method::Get, p) if p.starts_with("/api/attachments/") => {
            let raw_key = &p["/api/attachments/".len()..];
            // Percent-decode to handle any encoded characters in the key.
            let key = percent_encoding::percent_decode_str(raw_key)
                .decode_utf8_lossy()
                .into_owned();
            api_get_attachment(&key, env).await
        }

        // ── Admin auth ──
        (Method::Post, "/api/admin/login") => api_admin_login(&mut req, env).await,

        // ── Protected admin API ──
        (Method::Get, "/api/admin/messages") => {
            match check_auth(&req, env).await? {
                Some(_) => api_admin_get_messages(env).await,
                None => err_response("Unauthorized", 401),
            }
        }

        (m, p) if p.starts_with("/api/admin/messages/") => {
            match check_auth(&req, env).await? {
                None => err_response("Unauthorized", 401),
                Some(_) => {
                    let rest = &p["/api/admin/messages/".len()..];
                    if rest.ends_with("/approve") && m == Method::Put {
                        let id_str = rest.trim_end_matches("/approve");
                        let id = match id_str.parse::<i64>() {
                            Ok(n) if n > 0 => n,
                            _ => return err_response("Invalid message ID", 400),
                        };
                        api_approve_message(id, env).await
                    } else if m == Method::Delete {
                        let id = match rest.parse::<i64>() {
                            Ok(n) if n > 0 => n,
                            _ => return err_response("Invalid message ID", 400),
                        };
                        api_delete_message(id, env).await
                    } else {
                        err_response("Not found", 404)
                    }
                }
            }
        }

        _ => err_response("Not found", 404),
    }
}

// ─── Public Endpoint Handlers ─────────────────────────────────────────────────

async fn api_get_messages(env: &Env) -> Result<Response> {
    let db = env.d1("DB")?;
    let stmt = db.prepare(
        "SELECT id, name, email, content, attachment_key, approved, created_at \
         FROM messages WHERE approved = 1 ORDER BY created_at DESC LIMIT 50",
    );
    let result = stmt.all().await?;
    let messages = result.results::<Message>()?;
    ok_response(messages)
}

async fn api_create_message(req: &mut Request, env: &Env) -> Result<Response> {
    let body: NewMessage = match req.json().await {
        Ok(b) => b,
        Err(_) => return err_response("Invalid request body", 400),
    };

    let name = body.name.trim().to_string();
    let content = body.content.trim().to_string();

    if name.is_empty() {
        return err_response("Name is required", 400);
    }
    if name.len() > 100 {
        return err_response("Name must be 100 characters or fewer", 400);
    }
    if content.is_empty() {
        return err_response("Content is required", 400);
    }
    if content.len() > 2000 {
        return err_response("Content must be 2000 characters or fewer", 400);
    }
    if let Some(ref email) = body.email {
        if email.len() > 200 {
            return err_response("Email must be 200 characters or fewer", 400);
        }
    }

    let db = env.d1("DB")?;
    let email_js = body
        .email
        .as_deref()
        .filter(|e| !e.is_empty())
        .map_or(JsValue::null(), JsValue::from_str);
    let attachment_js = body
        .attachment_key
        .as_deref()
        .filter(|k| !k.is_empty())
        .map_or(JsValue::null(), JsValue::from_str);

    db.prepare(
        "INSERT INTO messages (name, email, content, attachment_key, approved) \
         VALUES (?1, ?2, ?3, ?4, 0)",
    )
    .bind(&[
        JsValue::from_str(&name),
        email_js,
        JsValue::from_str(&content),
        attachment_js,
    ])?
    .run()
    .await?;

    ok_response(serde_json::json!({"message": "留言已送出，等待審核後顯示"}))
}

async fn api_upload_attachment(req: &mut Request, env: &Env) -> Result<Response> {
    let bucket = match env.bucket("ATTACHMENTS") {
        Ok(b) => b,
        Err(_) => return err_response("Attachment storage not configured", 503),
    };

    let form_data = req.form_data().await?;

    let (bytes, filename) = match form_data.get("file") {
        Some(FormEntry::File(file)) => {
            let name = file.name();
            let bytes = file.bytes().await?;
            (bytes, name)
        }
        _ => return err_response("No file provided", 400),
    };

    if bytes.is_empty() {
        return err_response("Empty file", 400);
    }
    const MAX_SIZE: usize = 25 * 1024 * 1024; // 25 MB
    if bytes.len() > MAX_SIZE {
        return err_response("File exceeds 25 MB limit", 413);
    }

    let key = generate_attachment_key(&filename)?;
    bucket.put(&key, bytes).execute().await?;

    ok_response(serde_json::json!({"key": key}))
}

async fn api_get_attachment(key: &str, env: &Env) -> Result<Response> {
    // Guard against path traversal, null bytes, absolute paths, and empty keys
    if key.is_empty()
        || key.contains("..")
        || key.starts_with('/')
        || key.contains('\0')
    {
        return err_response("Invalid key", 400);
    }

    let bucket = match env.bucket("ATTACHMENTS") {
        Ok(b) => b,
        Err(_) => return err_response("Attachment storage not configured", 503),
    };

    match bucket.get(key).execute().await? {
        Some(object) => match object.body() {
            Some(body) => {
                let content_type = object
                    .http_metadata()
                    .content_type
                    .unwrap_or_else(|| "application/octet-stream".to_string());
                let safe_filename = key.split('/').next_back().unwrap_or("file");
                let bytes = body.bytes().await?;

                let headers = Headers::new();
                headers.set("Content-Type", &content_type)?;
                headers.set(
                    "Content-Disposition",
                    &format!("attachment; filename=\"{}\"", safe_filename),
                )?;

                Ok(Response::from_bytes(bytes)?.with_headers(headers))
            }
            None => err_response("File not available", 404),
        },
        None => err_response("File not found", 404),
    }
}

// ─── Admin Endpoint Handlers ──────────────────────────────────────────────────

async fn api_admin_login(req: &mut Request, env: &Env) -> Result<Response> {
    let body: LoginRequest = match req.json().await {
        Ok(b) => b,
        Err(_) => return err_response("Invalid request body", 400),
    };

    let admin_username = env
        .var("ADMIN_USERNAME")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "admin".to_string());

    let admin_password = match env.secret("ADMIN_PASSWORD") {
        Ok(s) => s.to_string(),
        Err(_) => return err_response("Admin not configured", 500),
    };

    let jwt_secret = match env.secret("JWT_SECRET") {
        Ok(s) => s.to_string(),
        Err(_) => return err_response("Server configuration error", 500),
    };

    if body.username != admin_username {
        return err_response("Invalid credentials", 401);
    }

    // Constant-time password comparison to prevent timing attacks
    use subtle::ConstantTimeEq;
    let password_match = body.password.as_bytes().ct_eq(admin_password.as_bytes());
    if !bool::from(password_match) {
        return err_response("Invalid credentials", 401);
    }

    let token = create_jwt(&body.username, &jwt_secret);
    ok_response(serde_json::json!({"token": token}))
}

async fn api_admin_get_messages(env: &Env) -> Result<Response> {
    let db = env.d1("DB")?;
    let stmt = db.prepare(
        "SELECT id, name, email, content, attachment_key, approved, created_at \
         FROM messages ORDER BY created_at DESC",
    );
    let result = stmt.all().await?;
    let messages = result.results::<Message>()?;
    ok_response(messages)
}

async fn api_approve_message(id: i64, env: &Env) -> Result<Response> {
    let db = env.d1("DB")?;
    db.prepare("UPDATE messages SET approved = 1 WHERE id = ?1")
        .bind(&[JsValue::from_f64(id as f64)])?
        .run()
        .await?;
    ok_response(serde_json::json!({"message": "Message approved"}))
}

async fn api_delete_message(id: i64, env: &Env) -> Result<Response> {
    let db = env.d1("DB")?;
    db.prepare("DELETE FROM messages WHERE id = ?1")
        .bind(&[JsValue::from_f64(id as f64)])?
        .run()
        .await?;
    ok_response(serde_json::json!({"message": "Message deleted"}))
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::sanitize_filename;

    // ── sanitize_filename ────────────────────────────────────────────────────
    //
    // These tests exercise the pure filename-sanitisation step that
    // generate_attachment_key delegates to.  The full key format produced by
    // generate_attachment_key is:
    //
    //   {unix_ms_timestamp}-{16 lowercase hex chars}/{safe_name}
    //
    // where {safe_name} == sanitize_filename(original_filename).

    #[test]
    fn sanitize_filename_keeps_alphanumeric_dot_dash_underscore() {
        assert_eq!(sanitize_filename("a.txt"), "a.txt");
        assert_eq!(sanitize_filename("my-file_1.png"), "my-file_1.png");
        assert_eq!(sanitize_filename("README.md"), "README.md");
    }

    #[test]
    fn sanitize_filename_strips_path_separators() {
        // Forward slashes – path traversal attempt.
        // Slashes are stripped; dots and alphanumerics are kept.
        // "../../etc/passwd" → dots and letters remain, slashes go → "....etcpasswd"
        let out = sanitize_filename("../../etc/passwd");
        assert!(!out.contains('/'), "output must not contain '/'");
        assert_eq!(out, "....etcpasswd");
    }

    #[test]
    fn sanitize_filename_strips_backslashes() {
        let out = sanitize_filename("a\\b.txt");
        assert!(!out.contains('\\'), "output must not contain backslash");
        assert_eq!(out, "ab.txt");
    }

    #[test]
    fn sanitize_filename_strips_spaces_and_special_chars_keeps_dot_dash_underscore() {
        let out = sanitize_filename("my file (1) [x].png");
        assert!(!out.contains(' '));
        assert!(!out.contains('('));
        assert!(!out.contains(')'));
        assert!(!out.contains('['));
        assert!(!out.contains(']'));
        assert!(out.ends_with(".png"), "extension dot must be preserved");
        assert_eq!(out, "myfile1x.png");
    }

    #[test]
    fn sanitize_filename_empty_input_falls_back_to_file() {
        assert_eq!(sanitize_filename(""), "file");
    }

    #[test]
    fn sanitize_filename_only_slashes_falls_back_to_file() {
        assert_eq!(sanitize_filename("/////"), "file");
    }

    #[test]
    fn sanitize_filename_only_spaces_falls_back_to_file() {
        assert_eq!(sanitize_filename("   "), "file");
    }

    #[test]
    fn sanitize_filename_only_special_chars_falls_back_to_file() {
        // All characters outside [A-Za-z0-9._-] are stripped; nothing remains.
        assert_eq!(sanitize_filename("!@#$%^&*()"), "file");
    }

    #[test]
    fn sanitize_filename_result_contains_only_allowed_chars() {
        let inputs = [
            "hello world!.png",
            "../../secret",
            "file<name>.txt",
            "a;b:c|d",
            "normal_file-1.txt",
        ];
        for input in &inputs {
            let out = sanitize_filename(input);
            for ch in out.chars() {
                assert!(
                    ch.is_alphanumeric() || ch == '.' || ch == '-' || ch == '_',
                    "unexpected char {ch:?} in sanitize_filename({input:?}) -> {out:?}"
                );
            }
        }
    }

    #[test]
    fn sanitize_filename_non_empty_result_is_never_empty() {
        // Even a filename made entirely of illegal chars must yield "file".
        let result = sanitize_filename("\0\x01\x02\x1f");
        assert!(!result.is_empty());
    }
}
