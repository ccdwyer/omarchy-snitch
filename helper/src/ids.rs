#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForbiddenApp(pub String);

impl std::fmt::Display for ForbiddenApp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "refusing to block identity '{}'", self.0)
    }
}

/// Aggregated other-uid / unresolved rows must never be migrated or IP-blocked.
pub fn is_forbidden_app(id: &str) -> bool {
    matches!(id, "system" | "unknown" | "" | "." | "..")
}

pub fn sanitize_app(id: &str) -> Result<String, String> {
    let trimmed = id.trim();
    if is_forbidden_app(&trimmed.to_ascii_lowercase()) {
        return Err(ForbiddenApp(trimmed.to_string()).to_string());
    }
    let s: String = id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let s = s.trim_matches('-').to_string();
    if s.is_empty() || s.len() > 64 {
        return Err("invalid app id".into());
    }
    if is_forbidden_app(&s) {
        return Err(ForbiddenApp(s).to_string());
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_system_and_unknown() {
        assert!(sanitize_app("system").is_err());
        assert!(sanitize_app("unknown").is_err());
        assert!(sanitize_app("SYSTEM").is_err());
        assert!(is_forbidden_app("system"));
        assert!(is_forbidden_app("unknown"));
    }

    #[test]
    fn accepts_firefox() {
        assert_eq!(sanitize_app("firefox").unwrap(), "firefox");
        assert_eq!(sanitize_app("org.mozilla.firefox").unwrap(), "org.mozilla.firefox");
    }
}
