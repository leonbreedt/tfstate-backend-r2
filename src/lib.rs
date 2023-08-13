#![allow(dead_code)]

use std::{cell::RefCell, rc::Rc};

use base64::Engine;
use serde::{Deserialize, Serialize};
use worker::*;

const PSK_SECRET_BINDING: &str = "psk";
const TFSTATE_BUCKET_BINDING: &str = "tfstate-bucket";
const TFSTATE_LOCK_BINDING: &str = "tfstate-lock";
const QUERY_PARAM_LOCK_ID: &str = "lock_id";
const LOCK_INFO_STORAGE_KEY: &str = "_lockInfo";

#[event(fetch, respond_with_errors)]
async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let router = Router::new();

    router
        .get_async("/health", |_req, ctx| async move {
            if ctx.secret(PSK_SECRET_BINDING).is_ok() {
                Response::ok("UP")
            } else {
                console_error!("missing secret '{}'", PSK_SECRET_BINDING);
                Response::error("DOWN", 500)
            }
        })
        .get_async("/state/:name", |req, ctx| async move {
            if is_authorized(&req, &ctx).await {
                match read_tfstate(&ctx).await {
                    Ok(bytes) => Response::from_bytes(bytes),
                    Err(e) => match e {
                        Error::Json((msg, status)) => Response::error(msg, status),
                        _ => Response::error(format!("{}", e), 500),
                    },
                }
            } else {
                Response::error("unauthorized", 403)
            }
        })
        .put_async("/state/:name", |mut req, ctx| async move {
            if is_authorized(&req, &ctx).await {
                match write_tfstate(&mut req, &ctx).await {
                    Ok(_) => Response::ok("updated"),
                    Err(e) => match e {
                        Error::Json((msg, status)) => Response::error(msg, status),
                        _ => Response::error(format!("{}", e), 500),
                    },
                }
            } else {
                Response::error("unauthorized", 403)
            }
        })
        .on_async("/state/:name/lock", |mut req, ctx| async move {
            if is_authorized(&req, &ctx).await {
                match lock_or_unlock_tfstate(&mut req, &ctx).await {
                    Ok(resp) => Ok(resp),
                    Err(e) => match e {
                        Error::Json((msg, status)) => Response::error(msg, status),
                        _ => Response::error(format!("{}", e), 500),
                    },
                }
            } else {
                Response::error("unauthorized", 403)
            }
        })
        .run(req, env)
        .await
}

async fn read_tfstate(ctx: &RouteContext<()>) -> Result<Vec<u8>> {
    let name = ctx
        .param("name")
        .ok_or(Error::Json(("missing name".to_string(), 400)))?;
    let bucket = ctx.bucket(TFSTATE_BUCKET_BINDING)?;
    let object_name = format!("{}.tfstate", name);
    let object = bucket
        .get(object_name)
        .execute()
        .await?
        .ok_or(Error::Json(("state not found".to_string(), 404)))?;
    let body = object
        .body()
        .ok_or(Error::Json(("empty state body".to_string(), 500)))?;
    body.bytes().await
}

async fn write_tfstate(req: &mut Request, ctx: &RouteContext<()>) -> Result<()> {
    let name = ctx
        .param("name")
        .ok_or(Error::Json(("missing name".to_string(), 400)))?;

    if let Some(existing_lock) = read_lock(&ctx, &name).await? {
        if let Some(lock_id) = query_param(&req, QUERY_PARAM_LOCK_ID) {
            // Already locked, and lock ID specified, must match.
            if lock_id != existing_lock.id {
                console_error!(
                    "already locked by another ID '{}', rejecting",
                    existing_lock.id
                );
                return Err(Error::Json(("already locked".to_string(), 423)));
            } else {
                console_debug!("already locked by our ID '{}', permitting", lock_id);
            }
        } else {
            console_error!(
                "already locked by another ID '{}', rejecting",
                existing_lock.id
            );
            return Err(Error::Json(("already locked".to_string(), 423)));
        }
    } else {
        console_log!("not locked, permitting tfstate update");
    }

    let object_name = format!("{}.tfstate", name);

    console_log!("updating '{}'...", object_name);

    let bucket = ctx.bucket(TFSTATE_BUCKET_BINDING)?;
    bucket
        .put(&object_name, req.bytes().await?)
        .execute()
        .await?;

    console_log!("updated of '{}' completed", object_name);

    Ok(())
}

async fn lock_or_unlock_tfstate(req: &mut Request, ctx: &RouteContext<()>) -> Result<Response> {
    let name = ctx
        .param("name")
        .ok_or(Error::Json(("missing name".to_string(), 400)))?;

    let namespace = ctx.durable_object(TFSTATE_LOCK_BINDING)?;
    let id = namespace.id_from_name(name)?;
    let stub = id.get_stub()?;

    stub.fetch_with_request(req.clone()?.into()).await
}

async fn read_lock(ctx: &RouteContext<()>, name: &str) -> Result<Option<LockInfo>> {
    let namespace = ctx.durable_object(TFSTATE_LOCK_BINDING)?;
    let id = namespace.id_from_name(name)?;
    let stub = id.get_stub()?;
    let mut response = stub
        .fetch_with_str("https://lock.local/state/{}/lock")
        .await?;
    if response.status_code() == 404 {
        Ok(None)
    } else {
        Ok(response.json().await.ok())
    }
}

async fn is_authorized(req: &Request, ctx: &RouteContext<()>) -> bool {
    if let Ok(secret) = ctx.secret(PSK_SECRET_BINDING) {
        if let Ok(Some(auth_header)) = req.headers().get("Authorization") {
            if let Some((method, value)) = auth_header.split_once(' ') {
                if method == "Basic" {
                    match base64::engine::general_purpose::URL_SAFE.decode(value) {
                        Ok(decoded) => {
                            let as_utf8 =
                                String::from_utf8(decoded).unwrap_or_else(|_| String::new());
                            if let Some((_, password)) = as_utf8.split_once(':') {
                                return secret.to_string() == password;
                            } else {
                                console_error!("credentials do not match");
                            }
                        }
                        Err(e) => {
                            console_error!("failed to decode credentials: {}", e);
                        }
                    }
                } else {
                    console_error!("unsupported authorization method '{}'", method);
                }
            } else {
                console_error!("malformed 'Authorization' header");
            }
        } else {
            console_error!("no 'Authorization' header");
        }
    } else {
        console_error!("missing secret '{}'", PSK_SECRET_BINDING);
    }
    false
}

fn query_param(req: &Request, name: &str) -> Option<String> {
    for (k, v) in req.url().unwrap().query_pairs() {
        if k == name {
            return Some(v.to_string());
        }
    }
    None
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ObjectLoadState {
    NotLoaded,
    Loaded,
}

#[durable_object]
pub struct TFStateLock {
    state: State,
    env: Env,
    load_state: ObjectLoadState,
    lock_info: Option<LockInfo>,
}

// JSON sent by Terraform backends.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LockInfo {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "Operation")]
    operation: String,
    #[serde(rename = "Info")]
    info: String,
    #[serde(rename = "Who")]
    who: String,
    #[serde(rename = "Version")]
    version: String,
    #[serde(rename = "Created")]
    created: String,
    #[serde(rename = "Path")]
    path: String,
}

#[durable_object]
impl DurableObject for TFStateLock {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            load_state: ObjectLoadState::NotLoaded,
            lock_info: None,
        }
    }

    async fn fetch(&mut self, req: Request) -> Result<Response> {
        self.load_if_needed().await?;

        let env = self.env.clone().into();
        let router = Router::with_data(Rc::new(RefCell::new(self)));

        router
            .get_async("/state/:name/lock", |_req, ctx| async move {
                let mut _self = ctx.data.borrow_mut();
                if let Some(lock_info) = &_self.lock_info {
                    Response::from_json(lock_info)
                } else {
                    Response::error("no lock found", 404)
                }
            })
            .put_async("/state/:name/lock", |mut req, ctx| async move {
                let mut _self = ctx.data.borrow_mut();
                if let Some(existing_lock) = &_self.lock_info {
                    Response::from_json(&serde_json::json!(existing_lock))
                        .map(|r| r.with_status(423))
                } else {
                    if let Some(lock_request) = req.json::<LockInfo>().await.ok() {
                        _self
                            .state
                            .storage()
                            .put(LOCK_INFO_STORAGE_KEY, &lock_request)
                            .await?;
                        Response::ok("locked")
                    } else {
                        Response::error("no lock ID", 400)
                    }
                }
            })
            .delete_async("/state/:name/lock", |mut req, ctx| async move {
                let mut _self = ctx.data.borrow_mut();
                if let Some(existing_lock) = &_self.lock_info {
                    if let Some(unlock_request) = req.json::<LockInfo>().await.ok() {
                        if unlock_request.id != existing_lock.id {
                            Response::from_json(&serde_json::json!(existing_lock))
                                .map(|r| r.with_status(423))
                        } else {
                            _self.state.storage().delete(LOCK_INFO_STORAGE_KEY).await?;
                            Response::ok("unlocked")
                        }
                    } else {
                        Response::error("invalid unlock request", 400)
                    }
                } else {
                    // Not an error to unlock if there is no lock.
                    Response::ok("unlocked")
                }
            })
            .or_else_any_method_async("*", |_req, _ctx| async move {
                Response::error("not found", 404)
            })
            .run(req, env)
            .await
    }
}

impl TFStateLock {
    async fn load_if_needed(&mut self) -> Result<()> {
        if let ObjectLoadState::NotLoaded = self.load_state {
            self.lock_info = self.state.storage().get(LOCK_INFO_STORAGE_KEY).await.ok();
            self.load_state = ObjectLoadState::Loaded;

            console_debug!(
                "loaded lock info from storage: '{}'",
                if let Some(info) = self.lock_info.as_ref() {
                    serde_json::to_string(info).ok().unwrap_or_else(String::new)
                } else {
                    String::new()
                }
            )
        }
        Ok(())
    }
}
