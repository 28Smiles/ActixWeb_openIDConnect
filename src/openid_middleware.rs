use std::fmt;
use std::fmt::{Display, Formatter};
use std::future::{ready, Ready};
use std::rc::Rc;
use std::str::FromStr;
use std::sync::Arc;

use actix_web::body::BoxBody;
use actix_web::cookie::{Cookie, SameSite};
use actix_web::dev::forward_ready;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::error::ErrorUnauthorized;
use actix_web::http::header::LOCATION;
use actix_web::http::StatusCode;
use actix_web::{error, get, web, Error, FromRequest, HttpMessage, HttpRequest, HttpResponse};
use futures_util::future::LocalBoxFuture;
use openidconnect::core::CoreGenderClaim;
use openidconnect::http::HeaderValue;
use openidconnect::{AccessToken, AuthorizationCode, EmptyAdditionalClaims, UserInfoClaims};
use serde::Deserialize;

use crate::openid::{IdToken, OpenID};

enum AuthCookies {
    AccessToken,
    IdToken,
    RefreshToken,
    UserInfo,
    Nonce,
}

impl Display for AuthCookies {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            AuthCookies::AccessToken => {
                write!(f, "access_token")
            }
            AuthCookies::IdToken => {
                write!(f, "id_token")
            }
            AuthCookies::RefreshToken => {
                write!(f, "refresh_token")
            }
            AuthCookies::UserInfo => {
                write!(f, "user_info")
            }
            AuthCookies::Nonce => {
                write!(f, "nonce")
            }
        }
    }
}

#[derive(Clone)]
pub struct AuthenticatedUser {
    pub access: UserInfoClaims<EmptyAdditionalClaims, CoreGenderClaim>,
}

#[derive(Clone, Debug, derive_more::Error)]
enum AuthError {
    NotAuthenticated { issuer_url: String, nonce: String },
}

impl Display for AuthError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::NotAuthenticated {
                issuer_url: _issuer_url,
                nonce: _nonce,
            } => {
                write!(f, "Not authenticated")
            }
        }
    }
}

impl error::ResponseError for AuthError {
    fn status_code(&self) -> StatusCode {
        match *self {
            AuthError::NotAuthenticated { .. } => StatusCode::FOUND,
        }
    }

    fn error_response(&self) -> HttpResponse<BoxBody> {
        let mut resp = HttpResponse::build(self.status_code()).body(self.to_string());
        match self {
            AuthError::NotAuthenticated { issuer_url, nonce } => {
                resp.add_cookie(&Cookie::build(AuthCookies::Nonce.to_string(), nonce)
                    .path("/")
                    .finish()
                ).unwrap();
                resp.headers_mut()
                    .insert(LOCATION, HeaderValue::from_str(issuer_url).unwrap());
                resp
            }
        }
    }
}

pub struct OpenIdMiddleware<S> {
    openid_client: Arc<OpenID>,
    service: Rc<S>,
    should_auth: fn(&ServiceRequest) -> bool,
}

impl<S> OpenIdMiddleware<S> {}

impl<S, B> Service<ServiceRequest> for OpenIdMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let srv = self.service.clone();
        let client = self.openid_client.clone();
        let client2 = self.openid_client.clone();
        let should_auth = self.should_auth;
        let path = req.path().to_string();

        let redirect_to_auth = move || -> AuthError {
            let url = client2.get_authorization_url(path.clone());
            AuthError::NotAuthenticated {
                issuer_url: url.url.to_string(),
                nonce: url.nonce.secret().to_string(),
            }
        };

        Box::pin(async move {
            let auth_user = match req.cookie(AuthCookies::AccessToken.to_string().as_str()) {
                None => if should_auth(&req) {
                    // Auth is not optional
                    return Err(redirect_to_auth().into())
                } else {
                    Err(redirect_to_auth())
                },
                Some(token) => {
                    let auth_user = client
                        .user_info(AccessToken::new(token.value().to_string()))
                        .await
                        .map_err(|_| redirect_to_auth())
                        .map(|user_info| AuthenticatedUser { access: user_info });
                    if auth_user.is_err() && should_auth(&req) {
                        return Err(redirect_to_auth().into());
                    }

                    auth_user
                }
            };
            req.extensions_mut().insert(auth_user);
            srv.call(req).await
        })
    }
}

pub struct AuthenticateMiddlewareFactory {
    client: Arc<OpenID>,
    should_auth: fn(&ServiceRequest) -> bool,
}

impl AuthenticateMiddlewareFactory {
    pub(crate) fn new(client: Arc<OpenID>, should_auth: fn(&ServiceRequest) -> bool) -> Self {
        AuthenticateMiddlewareFactory {
            client,
            should_auth,
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for AuthenticateMiddlewareFactory
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = OpenIdMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(OpenIdMiddleware {
            openid_client: self.client.clone(),
            service: Rc::new(service),
            should_auth: self.should_auth,
        }))
    }
}

#[derive(Deserialize)]
struct AuthQuery {
    code: String,
    state: String,
}

#[get("/logout")]
async fn logout_endpoint(
    req: HttpRequest,
    open_id_client: web::Data<Arc<OpenID>>,
) -> actix_web::Result<HttpResponse> {
    let id_token = match req.cookie(AuthCookies::IdToken.to_string().as_str()) {
        None => {
            log::debug!("No id token, redirecting to auth");
            return Err(error::ErrorBadRequest("missing id token"));
        }
        Some(id) => id.value().to_string(),
    };
    let logout_uri = open_id_client.get_logout_uri(&IdToken::from_str(id_token.as_str()).unwrap());
    let mut response = HttpResponse::Found();
    response.append_header((LOCATION, logout_uri.to_string()));
    Ok(response.finish())
}

#[get("/auth_callback")]
async fn auth_endpoint(
    req: HttpRequest,
    open_id_client: web::Data<Arc<OpenID>>,
    query: web::Query<AuthQuery>,
) -> actix_web::Result<HttpResponse> {
    let nonce = match req.cookie(AuthCookies::Nonce.to_string().as_str()) {
        None => {
            log::debug!("No nonce, redirecting to auth");
            return Err(error::ErrorBadRequest("No nonce"));
        }
        Some(n) => n.value().to_string(),
    };

    let tkn = match open_id_client
        .get_token(AuthorizationCode::new(query.code.to_string()))
        .await
    {
        Ok(tkn) => tkn,
        Err(e) => {
            log::warn!("Error getting token: {}", e);
            return Ok(HttpResponse::BadRequest().body(e.to_string()));
        }
    };
    let claim = match open_id_client.verify_id_token(&tkn.id_token, nonce).await {
        Ok(claim) => claim,
        Err(e) => {
            log::warn!("Error verifying id token: {}", e);
            return Err(error::ErrorInternalServerError("invalid id token"));
        }
    };
    let mut response = HttpResponse::Found();
    response
        .append_header((LOCATION, query.state.to_string()))
        .cookie(
            Cookie::build(
                AuthCookies::AccessToken.to_string(),
                tkn.access_token.secret(),
            )
            .same_site(SameSite::Lax)
            .secure(true)
            .finish(),
        )
        .cookie(
            Cookie::build::<String, String>(
                AuthCookies::UserInfo.to_string(),
                serde_json::to_string(claim).unwrap(),
            )
            .same_site(SameSite::Lax)
            .finish(),
        )
        .cookie(
            Cookie::build::<String, String>(
                AuthCookies::IdToken.to_string(),
                tkn.id_token.to_string(),
            )
            .same_site(SameSite::Lax)
            .secure(true)
            .finish(),
        );
    match tkn.refresh_token {
        Some(refresh_token) => Ok(response
            .cookie(
                Cookie::build(
                    AuthCookies::RefreshToken.to_string(),
                    refresh_token.secret(),
                )
                .same_site(SameSite::Lax)
                .secure(true)
                .finish(),
            )
            .finish()),
        None => Ok(response.finish()),
    }
}

pub struct Authenticated(AuthenticatedUser);

impl FromRequest for Authenticated {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(
        req: &HttpRequest,
        _payload: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        let value = req.extensions().get::<Result<AuthenticatedUser, AuthError>>().cloned();
        ready(match value {
            Some(Ok(v)) => Ok(Authenticated(v)),
            Some(Err(e)) => Err(e.into()),
            None => Err(ErrorUnauthorized("Unauthorized")),
        })
    }
}

impl std::ops::Deref for Authenticated {
    type Target = AuthenticatedUser;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub struct MaybeAuthenticated(Result<AuthenticatedUser, AuthError>);

impl FromRequest for MaybeAuthenticated {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(
        req: &HttpRequest,
        _payload: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        let value = req.extensions().get::<Result<AuthenticatedUser, AuthError>>().cloned();
        ready(match value {
            Some(v) => Ok(MaybeAuthenticated(v)),
            _ => Err(ErrorUnauthorized("Unauthorized")),
        })
    }
}

impl<'a> Into<Option<&'a AuthenticatedUser>> for &'a MaybeAuthenticated {
    fn into(self) -> Option<&'a AuthenticatedUser> {
        match &self.0 {
            Ok(v) => Some(v),
            _ => None,
        }
    }
}

impl<'a> TryInto<&'a AuthenticatedUser> for &'a MaybeAuthenticated {
    type Error = Error;

    fn try_into(self) -> Result<&'a AuthenticatedUser, Self::Error> {
        match &self.0 {
            Ok(v) => Ok(v),
            Err(e) => Err(e.clone().into()),
        }
    }
}
