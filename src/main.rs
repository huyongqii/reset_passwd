use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sqlx::{SqlitePool, Row};
use warp::{Filter, Rejection, Reply};
use warp::cors;
use chrono::{Utc, Duration};

#[derive(Deserialize, Serialize, Clone)]
struct PasswordResetRequest {
    username: String,
    email: String,
}

#[derive(Deserialize, Serialize)]
struct VerificationCode {
    username: String,
    code: String,
}

#[tokio::main]
async fn main() -> Result<(), sqlx::Error> {
    let db_pool = init_db().await?;
    let db_pool_filter = warp::any().map(move || db_pool.clone());

    let request_password_reset = warp::post()
        .and(warp::path("request_password_reset"))
        .and(warp::body::json())
        .and(db_pool_filter.clone())
        .and_then(handle_password_reset_request);

    let verify_code = warp::post()
        .and(warp::path("verify_code"))
        .and(warp::body::json())
        .and(db_pool_filter)
        .and_then(handle_verify_code);

    // 跨域
    let cors = cors()
        .allow_any_origin()
        .allow_methods(vec!["POST"])
        .allow_headers(vec!["Content-Type"]);

    let routes = request_password_reset.or(verify_code).with(cors);
    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;

    Ok(())
}

async fn init_db() -> Result<SqlitePool, sqlx::Error> {
    let database_url = "sqlite:./password_reset.db";
    println!("Database URL: {}", database_url);
    let db_pool = SqlitePool::connect(database_url).await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS password_resets (
            username TEXT PRIMARY KEY,
            email TEXT NOT NULL,
            code TEXT NOT NULL,
            expires_at INTEGER NOT NULL
        )",
    )
    .execute(&db_pool)
    .await?;

    Ok(db_pool)
}

async fn handle_password_reset_request(
    body: PasswordResetRequest,
    db_pool: SqlitePool,
) -> Result<impl Reply, Rejection> {
    let verification_code = generate_verification_code();
    println!("Generated verification code: {}", verification_code);

    // 计算过期时间：当前时间 + 10 分钟
    let expires_at = Utc::now() + Duration::minutes(10);
    let expires_at_timestamp = expires_at.timestamp();

    sqlx::query(
        "INSERT INTO password_resets (username, email, code, expires_at) VALUES (?, ?, ?, ?)
        ON CONFLICT(username) DO UPDATE SET code = excluded.code, expires_at = excluded.expires_at",
    )
    .bind(&body.username)
    .bind(&body.email)
    .bind(&verification_code)
    .bind(expires_at_timestamp)
    .execute(&db_pool)
    .await
    .map_err(|e| {
        println!("Failed to insert into database: {:?}", e);
        warp::reject()
    })?;

    send_verification_email(&body.email, &verification_code).await;

    Ok(warp::reply::json(&"Verification code sent. Please check your email."))
}

async fn handle_verify_code(
    body: VerificationCode,
    db_pool: SqlitePool,
) -> Result<impl Reply, Rejection> {
    println!("Received verification request for username: {}, code: {}", body.username, body.code);

    let row = sqlx::query(
        "SELECT code, expires_at FROM password_resets WHERE username = ?"
    )
    .bind(&body.username)
    .fetch_optional(&db_pool)
    .await
    .map_err(|e| {
        println!("Failed to fetch from database: {:?}", e);
        warp::reject()
    })?;

    if let Some(record) = row {
        let code: String = record.try_get("code").map_err(|e| {
            println!("Failed to retrieve code from database record: {:?}", e);
            warp::reject()
        })?;
        
        let expires_at: i64 = record.try_get("expires_at").map_err(|e| {
            println!("Failed to retrieve expires_at from database record: {:?}", e);
            warp::reject()
        })?;

        let current_timestamp = Utc::now().timestamp();

        if current_timestamp > expires_at {
            println!("Verification code for {} has expired.", body.username);
            return Ok(warp::reply::json(&"Verification code has expired."));
        }

        if code == body.code {
            println!("Verification successful for username: {}", body.username);
            Ok(warp::reply::json(&"Verification successful. You can now reset your password."))
        } else {
            println!("Verification code mismatch for username: {}", body.username);
            Ok(warp::reply::json(&"Verification code is incorrect."))
        }
    } else {
        println!("No record found for username: {}", body.username);
        Ok(warp::reply::json(&"Verification code not found."))
    }
}

fn generate_verification_code() -> String {
    let mut rng = rand::thread_rng();
    (0..6).map(|_| rng.gen_range(0..10).to_string()).collect()
}

async fn send_verification_email(recipient_email: &str, code: &str) {
    let email_subject = "Password Reset Verification Code";
    let email_body = format!(
        "Dear user,\n\nYou have requested to reset your password. Please use the following verification code to proceed:\n\nVerification Code: {}\n\nThis code will expire in 10 minutes.\n\nIf you did not request a password reset, please ignore this email.\n\nBest regards,\nSupport Team",
        code
    );

    let email = Message::builder()
        .from("yongqi_hu@163.com".parse().unwrap())
        .to(recipient_email.parse().unwrap())
        .subject(email_subject)
        .body(email_body)
        .unwrap();

    // 需要替换下这里
    let creds = Credentials::new("yongqi_hu@163.com".to_string(), "your_password".to_string());

    let mailer = SmtpTransport::relay("smtp.163.com")
        .unwrap()
        .credentials(creds)
        .build();

    match mailer.send(&email) {
        Ok(_) => println!("Email sent successfully to {:?}", recipient_email),
        Err(e) => println!("Could not send email: {:?}", e),
    }
}
