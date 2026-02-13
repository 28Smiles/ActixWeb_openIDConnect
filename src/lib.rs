//! Actix Web is a powerful, pragmatic, and extremely fast web framework for Rust.
//!
//! # Examples
//! Lightweight async OpenID Connect (OIDC) client and middleware for Actix-Web.
//! Support for the Authorization Code Flow
//! Documentation: https://github.com/RomainMichau/ActixWeb_openIDConnect
//!

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, LazyLock};

use crate::openid::OpenID;
use actix_web::dev::ServiceRequest;
use actix_web::web;
use actix_web::web::ServiceConfig;
use oauth2::{AsyncHttpClient, HttpClientError, HttpRequest, HttpResponse, RequestTokenError, StandardErrorResponse};
use oauth2::basic::BasicErrorResponseType;
use openidconnect::{reqwest, UserInfoError};
use url::Url;

mod openid;
pub mod openid_middleware;

#[derive(Clone)]
pub struct ActixWebOpenId<C = fn(HttpRequest) -> Pin<Box<dyn Future<Output=Result<HttpResponse, HttpClientError<reqwest::Error>>> + Send + Sync>>> {
    openid_client: Arc<OpenID<C>>,
    should_auth: fn(&ServiceRequest) -> bool,
    use_pkce: bool,
    redirect_path: String,
    logout_path: String,
}

pub struct ActixWebOpenIdBuilder<C = fn(HttpRequest) -> Pin<Box<dyn Future<Output=Result<HttpResponse, HttpClientError<reqwest::Error>>> + Send + Sync>>> {
    client_id: String,
    client_secret: Option<String>,
    redirect_url: Url,
    logout_path: String,
    issuer_url: String,
    should_auth: fn(&ServiceRequest) -> bool,
    post_logout_redirect_url: Option<String>,
    scopes: Vec<String>,
    additional_audiences: Vec<String>,
    use_pkce: bool,
    redirect_on_error: bool,
    allow_all_audiences: bool,
    async_http_client: C,
}

impl<C> ActixWebOpenIdBuilder<C> {
    pub fn client_secret(mut self, secret: impl Into<String>) -> Self {
        self.client_secret = Some(secret.into());
        self
    }

    pub fn should_auth(mut self, f: fn(&ServiceRequest) -> bool) -> Self {
        self.should_auth = f;
        self
    }

    pub fn post_logout_redirect_url(mut self, url: impl Into<String>) -> Self {
        self.post_logout_redirect_url = Some(url.into());
        self
    }

    pub fn logout_path(mut self, path: impl Into<String>) -> Self {
        self.logout_path = path.into();
        self
    }

    pub fn scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes;
        self
    }

    pub fn additional_audiences(mut self, audiences: Vec<String>) -> Self {
        self.additional_audiences = audiences;
        self
    }

    pub fn use_pkce(mut self, pkce: bool) -> Self {
        self.use_pkce = pkce;
        self
    }

    pub fn redirect_on_error(mut self, redirect_on_error: bool) -> Self {
        self.redirect_on_error = redirect_on_error;
        self
    }

    pub fn allow_all_audiences(mut self, allow_all_audiences: bool) -> Self {
        self.allow_all_audiences = allow_all_audiences;
        self
    }

    pub fn async_http_client<CN>(self, async_http_client: CN) -> ActixWebOpenIdBuilder<CN> {
        ActixWebOpenIdBuilder {
            client_id: self.client_id,
            client_secret: self.client_secret,
            redirect_url: self.redirect_url,
            logout_path: self.logout_path,
            issuer_url: self.issuer_url,
            should_auth: self.should_auth,
            post_logout_redirect_url: self.post_logout_redirect_url,
            scopes: self.scopes,
            additional_audiences: self.additional_audiences,
            use_pkce: self.use_pkce,
            redirect_on_error: self.redirect_on_error,
            allow_all_audiences: self.allow_all_audiences,
            async_http_client,
        }
    }
}

impl<C, F, E> ActixWebOpenIdBuilder<C>
    where
        C: Fn(HttpRequest) -> F + Send + Sync + 'static,
        F: Future<Output = Result<HttpResponse, E>> + 'static,
        E: std::error::Error + Send + Sync + 'static,
        anyhow::Error: From<UserInfoError<E>>,
        anyhow::Error: From<RequestTokenError<E, StandardErrorResponse<BasicErrorResponseType>>>,
{
    pub async fn build_and_init(self) -> anyhow::Result<ActixWebOpenId<C>> {
        Ok(ActixWebOpenId {
            openid_client: Arc::new(
                OpenID::init(
                    self.client_id,
                    self.client_secret,
                    self.redirect_url.clone(),
                    self.issuer_url,
                    self.post_logout_redirect_url,
                    self.scopes,
                    self.additional_audiences,
                    self.allow_all_audiences,
                    self.use_pkce,
                    self.redirect_on_error,
                    self.async_http_client,
                )
                .await?,
            ),
            redirect_path: self.redirect_url.path().to_string(),
            should_auth: self.should_auth,
            use_pkce: self.use_pkce,
            logout_path: self.logout_path,
        })
    }
}

fn default_http_client(req: HttpRequest) -> Pin<Box<dyn Future<Output=Result<HttpResponse, HttpClientError<reqwest::Error>>> + Send + Sync>> {
    static CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| reqwest::Client::builder().build().unwrap());
    CLIENT.call(req)
}

impl ActixWebOpenId {
    pub fn builder(
        client_id: String,
        redirect_url: String,
        issuer_url: String,
    ) -> ActixWebOpenIdBuilder {
        ActixWebOpenIdBuilder {
            client_id,
            client_secret: None,
            redirect_url: Url::parse(redirect_url.as_str()).expect("Invalid redirect URL"),
            logout_path: "/logout".to_string(),
            issuer_url,
            should_auth: |_| true, // default behavior
            post_logout_redirect_url: None,
            scopes: vec!["openid".into()],
            additional_audiences: vec![],
            use_pkce: false,
            redirect_on_error: false,
            allow_all_audiences: false,
            async_http_client: default_http_client,
        }
    }
}

impl<C, F, E> ActixWebOpenId<C>
    where
        C: Fn(HttpRequest) -> F + Send + Sync + 'static,
        F: Future<Output = Result<HttpResponse, E>> + 'static,
        E: std::error::Error + Send + Sync + 'static,
        anyhow::Error: From<UserInfoError<E>>,
        anyhow::Error: From<RequestTokenError<E, StandardErrorResponse<BasicErrorResponseType>>>,
{
    pub fn configure_open_id(&self) -> impl Fn(&mut ServiceConfig) + use<'_, C, F, E> {
        let client = self.openid_client.clone();
        move |cfg: &mut ServiceConfig| {
            cfg.service(
                web::resource(self.redirect_path.clone())
                    .route(web::get().to(openid_middleware::auth_endpoint::<C, F, E>)),
            )
            .service(
                web::resource(self.logout_path.clone())
                    .route(web::get().to(openid_middleware::logout_endpoint::<C, F, E>)),
            )
            .app_data(web::Data::new(client.clone()));
        }
    }

    pub fn get_middleware(&self) -> openid_middleware::AuthenticateMiddlewareFactory<C> {
        openid_middleware::AuthenticateMiddlewareFactory::new(
            self.openid_client.clone(),
            self.should_auth,
            self.use_pkce,
            self.redirect_path.clone(),
        )
    }
}
