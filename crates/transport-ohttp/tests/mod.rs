//! Behavior-focused tests, compiled as unit tests to inspect private channel state.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use axum::{body::Body, http::Request};
use fungi_transport::{RecvHalf, SendHalf, testkit};
use http_body_util::BodyExt;
use payjoin_mailroom::{db::files::FilesDb, directory::Service, ohttp_relay::SentinelTag};
use tokio::sync::Notify;
use tower::ServiceExt;

use crate::*;

use support::*;

mod cancellation;
mod channel;
mod pagination;
mod security;
mod support;
