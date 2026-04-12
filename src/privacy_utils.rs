//! Privacy utilities for URL sanitization and tracking prevention.
//!
//! Unified tracking parameter stripping across all BoomLeft applications.
//! Blocklist is compiled-in (not fetched remotely) so sanitisation works offline
//! and cannot be disabled by network attackers.

use url::Url;

/// Comprehensive list of known tracking query parameters across multiple tracking platforms.
///
/// This blocklist is maintained and updated per release. Apps update their tracking
/// prevention by updating the SDK dependency, not by fetching configuration remotely.
pub const TRACKING_PARAMS: &[&str] = &[
    // ── Google Analytics / Ads ──────────────────────────────────────
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "utm_id",
    "utm_referrer",
    "gclid",
    "gclsrc",
    "_ga",
    "_gl",
    "_gid",

    // ── Facebook / Meta ──────────────────────────────────────────────
    "fbclid",
    "fb_action_ids",
    "fb_action_types",
    "fb_source",
    "fb_ref",

    // ── Microsoft / Bing ────────────────────────────────────────────
    "msclkid",
    "msfpc",

    // ── TikTok ──────────────────────────────────────────────────────
    "ttclid",

    // ── Twitter / X ─────────────────────────────────────────────────
    "twclid",

    // ── Instagram ───────────────────────────────────────────────────
    "igshid",

    // ── LinkedIn ────────────────────────────────────────────────────
    "li_fat_id",

    // ── Adobe / Marketo ────────────────────────────────────────────
    "s_kwcid",
    "mkt_tok",
    "s_cid",

    // ── Pinterest ───────────────────────────────────────────────────
    "epik",

    // ── Mailchimp ───────────────────────────────────────────────────
    "mc_cid",
    "mc_eid",

    // ── HubSpot ─────────────────────────────────────────────────────
    "__hstc",
    "__hssc",
    "__hsfp",
    "_hsenc",
    "_hsmi",
    "hsCtaTracking",

    // ── Yandex ─────────────────────────────────────────────────────
    "yclid",
    "ymclid",

    // ── Drip ────────────────────────────────────────────────────────
    "__s",

    // ── Vero ────────────────────────────────────────────────────────
    "vero_id",
    "vero_conv",

    // ── Generic / Multi-platform ──────────────────────────────────
    "ref",
    "source",
    "_ke",
    "trk",
    "trkCampaign",
    "trkInfo",
    "clickid",
    "click_id",

    // ── Podcast-specific ───────────────────────────────────────────
    "ck_subscriber_id",

    // ── GIF provider tracking (Giphy, Klipy) ───────────────────────
    "cid",
    "rid",
    "ct",
    "ts",
    "random_id",
    "pingback_id",
];

/// Strip known tracking parameters from a URL.
///
/// Parses the URL, removes all query parameters matching the tracking blocklist,
/// and reconstructs the URL with proper percent-encoding. Returns the original
/// URL unchanged if parsing fails.
///
/// # Example
///
/// ```ignore
/// let url = "https://example.com/?utm_source=twitter&id=123";
/// let clean = strip_tracking_params(url).unwrap();
/// assert_eq!(clean, "https://example.com/?id=123");
/// ```
pub fn strip_tracking_params(url_str: &str) -> Result<String, String> {
    let mut parsed = Url::parse(url_str)
        .map_err(|e| format!("Invalid URL: {}", e))?;

    let cleaned: Vec<(String, String)> = parsed
        .query_pairs()
        .filter(|(key, _)| {
            let key_lower = key.to_lowercase();
            !TRACKING_PARAMS.iter().any(|&param| key_lower == param)
        })
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    if cleaned.is_empty() {
        parsed.set_query(None);
    } else {
        // Re-encode using the url crate's serializer to ensure proper percent-encoding
        let new_query = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(cleaned.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .finish();
        parsed.set_query(Some(&new_query));
    }

    Ok(parsed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_utm_params() {
        let url = "https://example.com/?utm_source=twitter&utm_medium=social&id=123";
        let clean = strip_tracking_params(url).unwrap();
        assert_eq!(clean, "https://example.com/?id=123");
    }

    #[test]
    fn test_strip_fbclid() {
        let url = "https://example.com/?fbclid=abc123&page=1";
        let clean = strip_tracking_params(url).unwrap();
        assert_eq!(clean, "https://example.com/?page=1");
    }

    #[test]
    fn test_empty_query_after_strip() {
        let url = "https://example.com/?utm_source=google&utm_medium=cpc";
        let clean = strip_tracking_params(url).unwrap();
        assert_eq!(clean, "https://example.com/");
    }

    #[test]
    fn test_preserves_safe_params() {
        let url = "https://example.com/?id=123&name=test&utm_source=twitter";
        let clean = strip_tracking_params(url).unwrap();
        assert!(clean.contains("id=123"));
        assert!(clean.contains("name=test"));
        assert!(!clean.contains("utm_source"));
    }

    #[test]
    fn test_case_insensitive_matching() {
        let url = "https://example.com/?UTM_SOURCE=google&gCLiD=abc";
        let clean = strip_tracking_params(url).unwrap();
        assert!(!clean.contains("UTM_SOURCE"));
        assert!(!clean.contains("gCLiD"));
    }

    #[test]
    fn test_invalid_url() {
        let result = strip_tracking_params("not a url");
        assert!(result.is_err());
    }
}
