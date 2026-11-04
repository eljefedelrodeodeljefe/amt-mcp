//! Operator guides compiled into the binary: setup (including the steps that
//! need a person at the device), security, recipes and troubleshooting. Served
//! as MCP resources (`amt://guide/<name>`) and through `list_guides`/`get_guide`.

pub struct Guide {
    pub name: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub text: &'static str,
}

pub const GUIDES: &[Guide] = &[
    Guide {
        name: "setup",
        title: "Setup",
        description: "Provisioning (client vs admin control mode), enabling SOL/IDE-R/KVM, host serial console, least privilege; marks the steps that need a human at the device",
        text: include_str!("../../../docs/guides/setup.md"),
    },
    Guide {
        name: "security",
        title: "Security",
        description: "Which ports to filter and where, credentials, control-mode caveats, firmware, audit",
        text: include_str!("../../../docs/guides/security.md"),
    },
    Guide {
        name: "recipes",
        title: "Recipes",
        description: "Recover a hung host, serial console, boot into BIOS, reinstall from an ISO over IDE-R, scheduled wake, audit review",
        text: include_str!("../../../docs/guides/recipes.md"),
    },
    Guide {
        name: "troubleshooting",
        title: "Troubleshooting",
        description: "Known failure modes and fixes: rpc-go stalls, MEBx password errors, consent, KVM framebuffer limit, connection limits",
        text: include_str!("../../../docs/guides/troubleshooting.md"),
    },
];

pub const URI_PREFIX: &str = "amt://guide/";

pub fn find(name_or_uri: &str) -> Option<&'static Guide> {
    let name = name_or_uri.strip_prefix(URI_PREFIX).unwrap_or(name_or_uri);
    GUIDES.iter().find(|g| g.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_guide_is_found_and_marks_human_steps_where_needed() {
        for g in GUIDES {
            assert!(find(g.name).is_some());
            assert!(find(&format!("{URI_PREFIX}{}", g.name)).is_some());
            assert!(g.text.starts_with("# "), "{} has no title", g.name);
        }
        assert!(find("setup").unwrap().text.contains("**Human"));
        assert!(find("nope").is_none());
    }
}
