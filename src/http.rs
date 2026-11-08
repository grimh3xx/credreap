//! HTTP authentication protocol: HTTP Basic and form-based login.

use std::time::Duration;

use regex::Regex;
use reqwest::{Client, Method};

use crate::scheduler::{Outcome, Protocol};

#[derive(Debug, Clone)]
pub enum HttpMode {
    /// HTTP Basic auth: success when the status is not 401/403.
    Basic,
    /// Form POST/GET with username/password fields.
    Form {
        user_field: String,
        pass_field: String,
        /// Extra static form fields (e.g. csrf tokens, `login=Submit`).
        extra: Vec<(String, String)>,
        method: Method,
    },
}

/// How to decide success from a response. Rules are checked in order:
/// explicit success signals win, then failure signals, then the default.
#[derive(Debug, Clone, Default)]
pub struct SuccessRule {
    /// Status codes that mean success (e.g. 302 after a login redirect).
    pub success_status: Vec<u16>,
    /// Body substring/regex that means success.
    pub success_match: Option<Regex>,
    /// Body substring/regex that means failure (e.g. "Invalid password").
    pub fail_match: Option<Regex>,
    /// Status codes that mean the account is locked (e.g. 423).
    pub locked_status: Vec<u16>,
}

pub struct HttpProtocol {
    client: Client,
    url: String,
    mode: HttpMode,
    rule: SuccessRule,
}

impl HttpProtocol {
    pub fn new(
        url: String,
        mode: HttpMode,
        rule: SuccessRule,
        insecure: bool,
        timeout: Duration,
    ) -> anyhow::Result<Self> {
        let client = Client::builder()
            .danger_accept_invalid_certs(insecure)
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none()) // we judge the 3xx ourselves
            .user_agent("credreap/0.1")
            .build()?;
        Ok(HttpProtocol {
            client,
            url,
            mode,
            rule,
        })
    }

    fn judge(&self, status: u16, body: &str) -> Outcome {
        if self.rule.locked_status.contains(&status) {
            return Outcome::Locked;
        }
        // Explicit success signals first.
        if self.rule.success_status.contains(&status) {
            return Outcome::Success;
        }
        if let Some(re) = &self.rule.success_match {
            if re.is_match(body) {
                return Outcome::Success;
            }
        }
        // Then explicit failure signals.
        if let Some(re) = &self.rule.fail_match {
            if re.is_match(body) {
                return Outcome::Failure;
            }
        }
        // Default heuristics when no explicit rule matched.
        match &self.mode {
            HttpMode::Basic => {
                if status == 401 || status == 403 {
                    Outcome::Failure
                } else if (200..400).contains(&status) {
                    Outcome::Success
                } else {
                    Outcome::Error
                }
            }
            HttpMode::Form { .. } => {
                // With a success-status set configured, non-match is failure;
                // otherwise a bare 200 is ambiguous and treated as failure.
                if self.rule.success_status.is_empty()
                    && self.rule.success_match.is_none()
                    && self.rule.fail_match.is_none()
                {
                    // No rule given: a 3xx redirect usually means success.
                    if (300..400).contains(&status) {
                        Outcome::Success
                    } else {
                        Outcome::Failure
                    }
                } else {
                    Outcome::Failure
                }
            }
        }
    }
}

#[async_trait::async_trait]
impl Protocol for HttpProtocol {
    async fn attempt(&self, user: &str, pass: &str) -> Outcome {
        let resp = match &self.mode {
            HttpMode::Basic => {
                self.client
                    .get(&self.url)
                    .basic_auth(user, Some(pass))
                    .send()
                    .await
            }
            HttpMode::Form {
                user_field,
                pass_field,
                extra,
                method,
            } => {
                let mut form: Vec<(String, String)> = vec![
                    (user_field.clone(), user.to_string()),
                    (pass_field.clone(), pass.to_string()),
                ];
                form.extend(extra.iter().cloned());
                let req = self.client.request(method.clone(), &self.url);
                let req = if method == Method::GET {
                    req.query(&form)
                } else {
                    req.form(&form)
                };
                req.send().await
            }
        };

        match resp {
            Ok(r) => {
                let status = r.status().as_u16();
                let body = r.text().await.unwrap_or_default();
                self.judge(status, &body)
            }
            Err(_) => Outcome::Error,
        }
    }

    fn describe(&self) -> String {
        let kind = match &self.mode {
            HttpMode::Basic => "http-basic".to_string(),
            HttpMode::Form { method, .. } => format!("http-form/{method}"),
        };
        format!("{kind} {}", self.url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn basic(rule: SuccessRule) -> HttpProtocol {
        HttpProtocol::new(
            "http://x".into(),
            HttpMode::Basic,
            rule,
            false,
            Duration::from_secs(5),
        )
        .unwrap()
    }

    #[test]
    fn basic_auth_default_judgement() {
        let p = basic(SuccessRule::default());
        assert_eq!(p.judge(200, ""), Outcome::Success);
        assert_eq!(p.judge(401, ""), Outcome::Failure);
        assert_eq!(p.judge(403, ""), Outcome::Failure);
    }

    #[test]
    fn fail_match_overrides_200() {
        let rule = SuccessRule {
            fail_match: Some(Regex::new("Invalid").unwrap()),
            ..Default::default()
        };
        let p = basic(rule);
        assert_eq!(p.judge(200, "Invalid password"), Outcome::Failure);
        assert_eq!(p.judge(200, "Welcome back"), Outcome::Success);
    }

    #[test]
    fn locked_status_detected() {
        let rule = SuccessRule {
            locked_status: vec![423],
            ..Default::default()
        };
        let p = basic(rule);
        assert_eq!(p.judge(423, ""), Outcome::Locked);
    }
}
