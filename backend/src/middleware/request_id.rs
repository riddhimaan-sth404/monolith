use axum::{extract::Request, middleware::Next, response::Response};
use uuid::Uuid;

pub struct RequestIdLayer;

pub async fn request_id_middleware(mut request: Request, next: Next) -> Result<Response, Response> {
    let request_id = request
        .headers()
        .get("X-Request-ID")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    request
        .extensions_mut()
        .insert(RequestId(request_id.clone()));

    let mut response = next.run(request).await;

    response
        .headers_mut()
        .insert("X-Request-ID", request_id.parse().unwrap());

    Ok(response)
}

#[derive(Clone, Debug)]
pub struct RequestId(pub String);
