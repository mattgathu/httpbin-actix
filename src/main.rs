//! HTTPBIN clone written in Rust using the actix-web framework.
use actix_session::Session;
use actix_web::{
    dev::BodyEncoding, get, http::header, http::ContentEncoding, http::Method, http::StatusCode,
    middleware, post, web, App, Error, HttpResponse, HttpServer, Responder, Route,
};
use base64;
use env_logger;
use futures::{self, StreamExt};
use maplit::hashmap;
use rand;
use rand::distributions::{Distribution, Uniform};
use serde::{Deserialize, Serialize};
use serde_json;
use tokio::time::delay_for;
use uuid;

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;

type HttpResponseResult = Result<HttpResponse, Error>;

static JSON_CONTENT_TYPE: &str = "application/json";
static ANGRY_ASCII: &str = r###"
          .-''''''-.
        .' _      _ '.
       /   O      O   \
      :                :
      |                |
      :       __       :
       \  .-"`  `"-.  /
        '.          .'
          '-......-'
     YOU SHOULDN'T BE HERE
"###;

static TEA_POT: &str = r###"
    -=[ teapot ]=-
       _...._
     .'  _ _ `.
    | ."` ^ `". _,
    \_;`"---"`|//
      |       ;/
      \_     _/
        `\"\"\"`
"###;

static ROBOT_TXT: &str = r###"User-agent: *
Disallow: /deny
"###;

fn headers_to_btreemap(hdrs: &header::HeaderMap) -> BTreeMap<&str, Option<&str>> {
    hdrs.iter()
        .map(|x| (x.0.as_str(), x.1.to_str().ok()))
        .collect::<BTreeMap<_, _>>()
}

fn query_string_to_btreemap(qs: &str) -> Option<BTreeMap<&str, &str>> {
    if qs.is_empty() {
        None
    } else {
        Some(
            qs.split('&')
                .map(|s| {
                    let sx = s.split('=').collect::<Vec<&str>>();
                    (sx[0], *sx.get(1).unwrap_or(&""))
                })
                .collect::<BTreeMap<_, _>>(),
        )
    }
}

trait JsonPrettyString: Serialize {
    fn to_pretty_string(&self) -> String {
        serde_json::to_string_pretty(&self).unwrap()
    }
}

#[derive(Serialize, Deserialize)]
struct AppState {
    name: String,
}

#[derive(Serialize, Deserialize)]
struct HelloResponse {
    msg: String,
}

#[derive(Serialize, Deserialize)]
struct GetResponse<'a> {
    #[serde(borrow)]
    args: Option<BTreeMap<&'a str, &'a str>>,
    headers: BTreeMap<&'a str, Option<&'a str>>,
    origin: Option<IpAddr>,
    url: String,
    id: Option<usize>,
}
impl JsonPrettyString for GetResponse<'_> {}

#[derive(Serialize, Deserialize)]
struct PostResponse<'a> {
    #[serde(borrow)]
    args: Option<BTreeMap<&'a str, &'a str>>,
    data: String,
    //files: BTreeMap<&'a str, Option<&'a str>>,
    forms: BTreeMap<String, String>,
    headers: BTreeMap<&'a str, Option<&'a str>>,
    //json: Option<BTreeMap<&'a str, &'a str>>,
    origin: Option<IpAddr>,
    url: String,
}
impl JsonPrettyString for PostResponse<'_> {}

#[derive(Serialize, Deserialize)]
struct Origin {
    origin: Option<IpAddr>,
}

#[derive(Serialize, Deserialize)]
struct Uuid {
    uuid: uuid::Uuid,
}

#[derive(Serialize, Deserialize)]
struct Headers<'a> {
    #[serde(borrow)]
    headers: BTreeMap<&'a str, Option<&'a str>>,
}
impl JsonPrettyString for Headers<'_> {}

#[derive(Serialize, Deserialize)]
struct BrotliResponse<'a> {
    brotli: bool,
    headers: BTreeMap<&'a str, Option<&'a str>>,
    method: &'a str,
    origin: Option<IpAddr>,
}
impl JsonPrettyString for BrotliResponse<'_> {}

#[derive(Serialize, Deserialize)]
struct RedirectRequest {
    url: String,
    status_code: Option<u16>,
}
impl JsonPrettyString for RedirectRequest {}

#[derive(Serialize, Deserialize)]
struct GzippedResponse<'a> {
    gzipped: bool,
    headers: BTreeMap<&'a str, Option<&'a str>>,
    method: &'a str,
    origin: Option<IpAddr>,
}
impl JsonPrettyString for GzippedResponse<'_> {}

#[derive(Serialize, Deserialize)]
struct DeflatedResponse<'a> {
    deflate: bool,
    headers: BTreeMap<&'a str, Option<&'a str>>,
    method: &'a str,
    origin: Option<IpAddr>,
}
impl JsonPrettyString for DeflatedResponse<'_> {}

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok().json(HelloResponse {
        msg: "Http.rs 🌈".to_string(),
    })
}

/// Returns page denied by robots.txt rules.
#[get("/deny")]
async fn deny() -> impl Responder {
    HttpResponse::Ok().body(ANGRY_ASCII)
}

/// Returns some robots.txt rules.
#[get("/robots.txt")]
async fn robots() -> impl Responder {
    HttpResponse::Ok().body(ROBOT_TXT)
}

/// Returns the request's query parameters.
#[get("/get")]
async fn get(req: web::HttpRequest) -> impl Responder {
    HttpResponse::Ok().content_type(JSON_CONTENT_TYPE).body(
        GetResponse {
            url: req.uri().to_string(),
            headers: headers_to_btreemap(req.headers()),
            origin: req.peer_addr().map(|a| a.ip()),
            args: query_string_to_btreemap(req.query_string()),
            id: None,
        }
        .to_pretty_string(),
    )
}

/// Returns the request's POST parameters.
#[post("/post")]
async fn view_post(
    req: web::HttpRequest,
    form: web::Form<BTreeMap<String, String>>,
    mut body: web::Payload,
) -> HttpResponseResult {
    let mut bytes = web::BytesMut::new();
    while let Some(item) = body.next().await {
        bytes.extend_from_slice(&item?);
    }
    Ok(HttpResponse::Ok().content_type(JSON_CONTENT_TYPE).body(
        PostResponse {
            url: req.uri().to_string(),
            headers: headers_to_btreemap(req.headers()),
            origin: req.peer_addr().map(|a| a.ip()),
            args: query_string_to_btreemap(req.query_string()),
            forms: form.into_inner(),
            data: format!("{:?}!", bytes),
        }
        .to_pretty_string(),
    ))
}

/// Returns the requester's IP Address.
#[get("/ip")]
async fn get_origin(req: web::HttpRequest) -> impl Responder {
    HttpResponse::Ok().json(Origin {
        origin: req.peer_addr().map(|a| a.ip()),
    })
}

/// Returns the incoming requests's User-Agent header.
#[get("/user-agent")]
async fn user_agent(req: web::HttpRequest) -> impl Responder {
    let ua = req.headers().get(header::USER_AGENT);
    let map = hashmap! {"user-agent"=> ua.and_then(|u| u.to_str().ok())};
    HttpResponse::Ok().json(map)
}

/// Returns the incoming request's HTTP headers.
#[get("/headers")]
async fn get_headers(req: web::HttpRequest) -> impl Responder {
    HttpResponse::Ok().content_type(JSON_CONTENT_TYPE).body(
        Headers {
            headers: req
                .headers()
                .iter()
                .map(|x| (x.0.as_str(), x.1.to_str().ok()))
                .collect::<BTreeMap<_, _>>(),
        }
        .to_pretty_string(),
    )
}

/// Returns GZip-encoded data.
#[get("/gzip")]
async fn gzip(req: web::HttpRequest) -> impl Responder {
    let headers = req
        .headers()
        .iter()
        .map(|x| (x.0.as_str(), x.1.to_str().ok()))
        .collect::<BTreeMap<_, _>>();
    let method = req.method().as_str();
    let origin = req.peer_addr().map(|a| a.ip());
    let gzipped = true;

    let resp = GzippedResponse {
        origin,
        headers,
        method,
        gzipped,
    }
    .to_pretty_string();
    HttpResponse::Ok()
        .encoding(ContentEncoding::Gzip)
        .content_type(JSON_CONTENT_TYPE)
        .body(resp)
}

/// Returns Deflate-encoded data.
#[get("/deflate")]
async fn deflate(req: web::HttpRequest) -> impl Responder {
    let headers = req
        .headers()
        .iter()
        .map(|x| (x.0.as_str(), x.1.to_str().ok()))
        .collect::<BTreeMap<_, _>>();
    let method = req.method().as_str();
    let origin = req.peer_addr().map(|a| a.ip());
    let deflate = true;

    let resp = DeflatedResponse {
        origin,
        headers,
        method,
        deflate,
    }
    .to_pretty_string();
    HttpResponse::Ok()
        .encoding(ContentEncoding::Deflate)
        .content_type(JSON_CONTENT_TYPE)
        .body(resp)
}

/// Returns Brotli-encoded data.
#[get("/brotli")]
async fn brotli(req: web::HttpRequest) -> impl Responder {
    let headers = req
        .headers()
        .iter()
        .map(|x| (x.0.as_str(), x.1.to_str().ok()))
        .collect::<BTreeMap<_, _>>();
    let method = req.method().as_str();
    let origin = req.peer_addr().map(|a| a.ip());
    let brotli = true;

    let resp = BrotliResponse {
        origin,
        headers,
        method,
        brotli,
    }
    .to_pretty_string();
    HttpResponse::Ok()
        .encoding(ContentEncoding::Br)
        .content_type(JSON_CONTENT_TYPE)
        .body(resp)
}

/// Returns a UUID4.
#[get("/uuid")]
async fn uuid_v4() -> impl Responder {
    HttpResponse::Ok().json(Uuid {
        uuid: uuid::Uuid::new_v4(),
    })
}

/// Decodes base64url-encoded string.
#[get("/base64/{value}")]
async fn decode_base64(value: web::Path<String>) -> impl Responder {
    let decoded = match base64::decode_config(value.as_bytes(), base64::URL_SAFE) {
        Ok(bytes) => bytes,
        Err(_) => "Incorrect Base64 data try: SFRUUFJTIGlzIGF3ZXNvbWU"
            .as_bytes()
            .to_vec(),
    };
    HttpResponse::Ok().body(decoded)
}

/// Returns status code or random status code if more than one are given
async fn view_status(codes: web::Path<String>) -> HttpResponseResult {
    let code = if !codes.contains(",") {
        StatusCode::from_bytes(codes.as_bytes()).unwrap()
    } else {
        let codes_vec = codes.split(',').collect::<Vec<_>>();
        let mut rng = rand::thread_rng();
        let die = Uniform::from(1..(codes_vec.len() - 1));
        let idx = die.sample(&mut rng);
        StatusCode::from_bytes(codes_vec[idx as usize].as_bytes()).unwrap()
    };
    if code.as_u16() == 418 {
        Ok(HttpResponse::build(code).body(TEA_POT))
    } else {
        Ok(HttpResponse::build(code).finish())
    }
}

/// Returns cookie data
#[get("/cookies")]
async fn view_cookies(_session: Session) -> HttpResponseResult {
    todo!();
}

/// Sets cookie(s) as provided by the query string and redirects to cookie list.
#[get("/cookies/set")]
async fn set_cookies(sess: Session, req: web::HttpRequest) -> HttpResponseResult {
    match query_string_to_btreemap(req.query_string()) {
        None => {}
        Some(map) => {
            for (key, val) in map.iter() {
                sess.set(key, val)?;
            }
        }
    }
    Ok(HttpResponse::Ok().body(""))
}

/// Deletes one or more cookies.
#[get("/cookies/delete")]
async fn delete_cookies(sess: Session, req: web::HttpRequest) -> HttpResponseResult {
    match query_string_to_btreemap(req.query_string()) {
        None => {}
        Some(map) => {
            for (key, _) in map.iter() {
                sess.remove(key);
            }
        }
    }
    Ok(HttpResponse::Ok().body(""))
}

/// Sets a Cache-Control header for _n_ seconds.
#[get("/cache/{n}")]
async fn set_cache(n: web::Path<usize>, req: web::HttpRequest) -> HttpResponseResult {
    Ok(HttpResponse::Ok()
        .set_header(
            header::HeaderName::from_lowercase(b"cache-control").unwrap(),
            header::HeaderValue::from_str(&format!("public, max-age={}", n))?,
        )
        .content_type(JSON_CONTENT_TYPE)
        .body(
            GetResponse {
                url: req.uri().to_string(),
                headers: headers_to_btreemap(req.headers()),
                origin: req.peer_addr().map(|a| a.ip()),
                args: query_string_to_btreemap(req.query_string()),
                id: None,
            }
            .to_pretty_string(),
        ))
}

/// Delays responding for _min(n, 10)_ seconds.
#[get("/delay/{n}")]
async fn delay(n: web::Path<u64>, req: web::HttpRequest) -> HttpResponseResult {
    let n = std::cmp::min(n.into_inner(), 10);
    delay_for(Duration::from_secs(n)).await;
    Ok(HttpResponse::Ok().content_type(JSON_CONTENT_TYPE).body(
        GetResponse {
            url: req.uri().to_string(),
            headers: headers_to_btreemap(req.headers()),
            origin: req.peer_addr().map(|a| a.ip()),
            args: query_string_to_btreemap(req.query_string()),
            id: None,
        }
        .to_pretty_string(),
    ))
}

/// Stream n JSON responses
#[get("/stream/{n}")]
async fn stream_messages(n: web::Path<usize>, req: web::HttpRequest) -> HttpResponseResult {
    let stream = (0..=n.into_inner()).map(move |id| {
        let resp = GetResponse {
            url: req.uri().to_string(),
            headers: headers_to_btreemap(req.headers()),
            origin: req.peer_addr().map(|a| a.ip()),
            args: query_string_to_btreemap(req.query_string()),
            id: Some(id),
        };
        let i: Result<bytes::Bytes, Error> =
            Ok(bytes::Bytes::from(serde_json::to_string(&resp).unwrap()));
        i
    });
    let body = futures::stream::iter(stream);
    Ok(HttpResponse::Ok()
        .content_type(JSON_CONTENT_TYPE)
        .streaming(body))
}

/// 302/3XX Redirects to the given URL.
#[get("/redirect-to")]
async fn redirect_to(web::Query(info): web::Query<RedirectRequest>) -> impl Responder {
    match info.status_code {
        None => HttpResponse::Found()
            .set_header(header::LOCATION, info.url)
            .finish(),
        Some(code) => match code {
            301 => HttpResponse::MovedPermanently()
                .set_header(header::LOCATION, info.url)
                .finish(),
            302 => HttpResponse::Found()
                .set_header(header::LOCATION, info.url)
                .finish(),
            303 => HttpResponse::SeeOther()
                .set_header(header::LOCATION, info.url)
                .finish(),
            304 => HttpResponse::NotModified()
                .set_header(header::LOCATION, info.url)
                .finish(),
            305 => HttpResponse::UseProxy()
                .set_header(header::LOCATION, info.url)
                .finish(),
            307 => HttpResponse::TemporaryRedirect()
                .set_header(header::LOCATION, info.url)
                .finish(),
            308 => HttpResponse::PermanentRedirect()
                .set_header(header::LOCATION, info.url)
                .finish(),
            _ => HttpResponse::build(StatusCode::from_u16(code).unwrap_or(StatusCode::FOUND))
                .set_header(header::LOCATION, info.url)
                .finish(),
        },
    }
}

/// App
#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "actix_web=info");
    env_logger::init();

    // todo: use logging for this
    println!("Starting up actix server");
    println!("Listening on port 80");

    HttpServer::new(|| {
        App::new()
            .data(AppState {
                name: "http-rs".to_string(),
            })
            .wrap(middleware::Logger::default())
            .wrap(middleware::Compress::default())
            .service(brotli)
            .service(decode_base64)
            .service(deflate)
            .service(delay)
            .service(deny)
            .service(get)
            .service(get_headers)
            .service(get_origin)
            .service(gzip)
            .service(index)
            .service(redirect_to)
            .service(robots)
            .service(stream_messages)
            .service(user_agent)
            .service(uuid_v4)
            .route("/status/{codes}", web::get().to(view_status))
            .route("/status/{codes}", web::post().to(view_status))
            .route("/status/{codes}", web::patch().to(view_status))
            .route("/status/{codes}", web::put().to(view_status))
            .route("/status/{codes}", web::delete().to(view_status))
            .route(
                "/status/{codes}",
                Route::new().method(Method::TRACE).to(view_status),
            )
    })
    .bind("0.0.0.0:80")?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::http;
    use actix_web::test;
    use actix_web::App;

    macro_rules! get_test {
        ($name:ident, $uri:expr, $service:ident, $status:ident, $json: ident) => {
            #[actix_rt::test]
            async fn $name() {
                let mut app = test::init_service(App::new().service($service)).await;
                let req = test::TestRequest::with_header("content-type", "application/json")
                    .uri($uri)
                    .to_request();
                let mut resp = test::call_service(&mut app, req).await;
                assert_eq!(resp.status(), http::StatusCode::$status);
                let (bytes, _) = resp.take_body().into_future().await;
                assert!(serde_json::from_slice::<$json>(&bytes.unwrap().unwrap()).is_ok())
            }
        };
    }

    get_test!(test_index, "/", index, OK, HelloResponse);
    get_test!(test_ip, "/ip", get_origin, OK, Origin);
    get_test!(test_get, "/get", get, OK, GetResponse);
    get_test!(test_headers, "/headers", get_headers, OK, Headers);
    get_test!(test_gzip, "/gzip", gzip, OK, GzippedResponse);
    get_test!(test_deflate, "/deflate", deflate, OK, DeflatedResponse);
    get_test!(test_brotli, "/brotli", brotli, OK, BrotliResponse);
    get_test!(test_uuid, "/uuid", uuid_v4, OK, Uuid);

    #[actix_rt::test]
    async fn test_deny() {
        let mut app = test::init_service(App::new().service(deny)).await;
        let req = test::TestRequest::with_header("content-type", "text/plain")
            .uri("/deny")
            .to_request();
        let mut resp = test::call_service(&mut app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);
        let (bytes, _) = resp.take_body().into_future().await;
        assert_eq!(ANGRY_ASCII.as_bytes(), bytes.unwrap().unwrap());
    }

    #[actix_rt::test]
    async fn test_robots() {
        let mut app = test::init_service(App::new().service(robots)).await;
        let req = test::TestRequest::with_header("content-type", "text/plain")
            .uri("/robots.txt")
            .to_request();
        let mut resp = test::call_service(&mut app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);
        let (bytes, _) = resp.take_body().into_future().await;
        assert_eq!(ROBOT_TXT.as_bytes(), bytes.unwrap().unwrap());
    }
}
