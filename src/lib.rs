use worker::*;

#[event(fetch)]
async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let router = Router::new();

    router
        .get_async("/health", |_req, ctx| async move {
            if ctx.secret("PSK").is_ok() && ctx.var("BUCKET").is_ok() {
                Response::ok("UP")
            } else {
                Response::error("DOWN", 500)
            }
        })
        .get_async("/state/:name", |req, ctx| async move {
            if is_authorized(&req, &ctx).await {
                if let Ok(bucket_name) = ctx.var("BUCKET") {
                    match ctx.bucket(&bucket_name.to_string()) {
                        Ok(bucket) => {
                            if let Some(name) = ctx.param("name") {
                                if let Ok(Some(obj)) =
                                    bucket.get(format!("{}.tfstate", name)).execute().await
                                {
                                    if let Some(body) = obj.body() {
                                        if let Ok(bytes) = body.bytes().await {
                                            Response::from_bytes(bytes)
                                        } else {
                                            Response::error("body read error", 500)
                                        }
                                    } else {
                                        Response::error("empty object", 500)
                                    }
                                } else {
                                    Response::error("state read error", 500)
                                }
                            } else {
                                Response::error("no such bucket", 500)
                            }
                        }
                        Err(e) => Response::error(format!("bucket error: {}", e), 500),
                    }
                } else {
                    Response::error("missing bucket name", 500)
                }
            } else {
                Response::error("unauthorized", 401)
            }
        })
        .run(req, env)
        .await
}

async fn is_authorized(req: &Request, ctx: &RouteContext<()>) -> bool {
    if let Ok(secret) = ctx.secret("PSK") {
        if let Ok(Some(auth_header)) = req.headers().get("Authorization") {
            if let Some((method, value)) = auth_header.split_once(" ") {
                if method == "Basic" {
                    if let Ok(decoded) = base64::decode(value) {
                        let as_utf8 = String::from_utf8(decoded).unwrap_or_else(|_| String::new());
                        if let Some((_, password)) = as_utf8.split_once(':') {
                            return secret.to_string() == password;
                        }
                    }
                }
            }
        }
    }
    false
}
