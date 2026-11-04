use shadow_core::ShadowPolicy;
use std::collections::HashMap;

pub fn filter_environment(
    policy: &ShadowPolicy,
    explicit_env: &[String],
) -> HashMap<String, String> {
    let mut filtered = HashMap::new();

    for (k, v) in std::env::vars() {
        if policy.is_variable_permitted(&k, explicit_env) {
            filtered.insert(k, v);
        }
    }

    // Ensure HOME and PATH have safe fallbacks if missing
    filtered.entry("PATH".to_string()).or_insert_with(|| {
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string()
    });

    filtered
}
