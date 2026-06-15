use axum::Router;
use crate::app::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
}
