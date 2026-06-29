use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteTargetType {
    Internal,
    External,
}

impl RouteTargetType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Internal => "internal",
            Self::External => "external",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LandingMode {
    Default,
    Template,
}

impl LandingMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Template => "template",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VisitVariant {
    Real,
    Fake,
    Probe,
    Unknown,
}

impl VisitVariant {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Real => "real",
            Self::Fake => "fake",
            Self::Probe => "probe",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    pub id: Uuid,
    pub name: String,
    pub entry_domain: String,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromoCode {
    pub id: Uuid,
    pub route_id: Uuid,
    pub code: String,
    pub name: String,
    pub apk_url: Option<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
}
