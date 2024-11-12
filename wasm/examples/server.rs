use axum::Router;
use std::net::SocketAddr;
use tower::ServiceExt;
use tower_http::{services::ServeDir, trace::TraceLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                format!("{}=debug,tower_http=debug", env!("CARGO_CRATE_NAME")).into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tokio::join!(serve(using_serve_dir(), 3001),);
}

fn using_serve_dir() -> Router {
    let service = ServiceExt::<axum::http::Request<()>>::map_response(
        ServeDir::new("www"),
        |mut response| {
            response.headers_mut().insert(
                "Cross-Origin-Embedder-Policy",
                "require-corp".parse().unwrap(),
            );
            response
                .headers_mut()
                .insert("Cross-Origin-Opener-Policy", "same-origin".parse().unwrap());
            response
        },
    );

    Router::new().nest_service("/", service)
}

async fn serve(app: Router, port: u16) {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app.layer(TraceLayer::new_for_http()))
        .await
        .unwrap();
}
