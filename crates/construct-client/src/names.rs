//! The name shown for a person who chose none: an adjective and an animal (or, one time in five,
//! an IT noun), picked by the SHA-256 of their account id. iOS's `DisplayNameGenerator` and
//! Android compute the same, so a person is called the same on every client. The word lists are
//! copied from iOS in order, repeats included: the index is taken modulo their length.

use sha2::{Digest, Sha256};

/// The generated name of `user_id`, lower case, as iOS shows it ("silent dolphin").
pub fn generated(user_id: &str) -> String {
    let hash = Sha256::digest(user_id.as_bytes());
    let index = |at: usize, len: usize| {
        let value = u32::from_be_bytes([hash[at], hash[at + 1], hash[at + 2], hash[at + 3]]);
        value as usize % len
    };
    let adjective = ADJECTIVES[index(0, ADJECTIVES.len())];
    let noun = if hash[8] % 5 == 0 {
        IT_NOUNS[index(4, IT_NOUNS.len())]
    } else {
        ANIMALS[index(4, ANIMALS.len())]
    };
    format!("{adjective} {noun}")
}

/// Whether `name` is only `user_id`'s generated name — no choice of the person. Android writes it
/// in another case, so case is ignored.
pub fn is_generated(name: &str, user_id: &str) -> bool {
    name.trim().eq_ignore_ascii_case(&generated(user_id))
}

/// The name a person is shown by, as iOS resolves it (`ContactName.resolved`): the name they
/// shared unless it is only their generated one, then their username, then the generated name.
pub fn resolved(display_name: &str, username: &str, user_id: &str) -> String {
    let display_name = display_name.trim();
    if !display_name.is_empty() && !is_generated(display_name, user_id) {
        return display_name.to_owned();
    }
    let username = username.trim();
    if !username.is_empty() {
        return username.to_owned();
    }
    generated(user_id)
}

const ADJECTIVES: [&str; 102] = [
    "silent",
    "happy",
    "swift",
    "brave",
    "gentle",
    "calm",
    "bright",
    "bold",
    "quick",
    "quiet",
    "wise",
    "noble",
    "free",
    "kind",
    "pure",
    "jolly",
    "witty",
    "fierce",
    "proud",
    "sly",
    "lucky",
    "cheerful",
    "jovial",
    "merry",
    "clever",
    "cunning",
    "valiant",
    "humble",
    "clear",
    "cool",
    "warm",
    "soft",
    "strong",
    "wild",
    "misty",
    "sunny",
    "cloudy",
    "starry",
    "frosty",
    "stormy",
    "ember",
    "blazing",
    "frozen",
    "mountain",
    "ocean",
    "river",
    "forest",
    "desert",
    "volcanic",
    "thunder",
    "solar",
    "lunar",
    "celestial",
    "crystal",
    "golden",
    "silver",
    "copper",
    "obsidian",
    "amber",
    "crimson",
    "azure",
    "verdant",
    "sleek",
    "sharp",
    "smooth",
    "tall",
    "deep",
    "light",
    "dark",
    "ancient",
    "agile",
    "majestic",
    "elegant",
    "graceful",
    "giant",
    "tiny",
    "nimble",
    "radiant",
    "gleaming",
    "shadowy",
    "whispering",
    "echoing",
    "vivid",
    "mystic",
    "hidden",
    "lonely",
    "weathered",
    "deprecated",
    "recursive",
    "async",
    "frozen",
    "nested",
    "compiled",
    "broken",
    "pending",
    "idle",
    "verbose",
    "headless",
    "orphaned",
    "forked",
    "stale",
    "cursed",
];

const ANIMALS: [&str; 101] = [
    "fox",
    "wolf",
    "bear",
    "lion",
    "tiger",
    "panda",
    "jaguar",
    "panther",
    "leopard",
    "cheetah",
    "lynx",
    "cougar",
    "hyena",
    "jackal",
    "dingo",
    "wolverine",
    "otter",
    "seal",
    "orca",
    "dolphin",
    "whale",
    "shark",
    "ferret",
    "mongoose",
    "badger",
    "deer",
    "moose",
    "elk",
    "bison",
    "hare",
    "rabbit",
    "squirrel",
    "beaver",
    "hedgehog",
    "bat",
    "boar",
    "ox",
    "ram",
    "stag",
    "marten",
    "meerkat",
    "eagle",
    "hawk",
    "owl",
    "raven",
    "falcon",
    "swan",
    "dove",
    "crane",
    "heron",
    "sparrow",
    "robin",
    "finch",
    "wren",
    "phoenix",
    "crow",
    "vulture",
    "albatross",
    "kingfisher",
    "kestrel",
    "harrier",
    "gull",
    "penguin",
    "peacock",
    "parrot",
    "hornbill",
    "nightjar",
    "dragon",
    "griffin",
    "unicorn",
    "pegasus",
    "basilisk",
    "chimera",
    "kraken",
    "hydra",
    "manticore",
    "gryphon",
    "yeti",
    "kitsune",
    "sphinx",
    "serpent",
    "cobra",
    "viper",
    "python",
    "rattler",
    "gecko",
    "iguana",
    "scorpion",
    "spider",
    "mantis",
    "beetle",
    "butterfly",
    "moth",
    "dragonfly",
    "mammoth",
    "saber",
    "raptor",
    "tricera",
    "rex",
    "titan",
    "direwolf",
];

const IT_NOUNS: [&str; 58] = [
    "printer",
    "keyboard",
    "monitor",
    "server",
    "router",
    "modem",
    "firewall",
    "switch",
    "hub",
    "rack",
    "cable",
    "dongle",
    "cursor",
    "terminal",
    "daemon",
    "kernel",
    "process",
    "thread",
    "socket",
    "buffer",
    "pointer",
    "callback",
    "semaphore",
    "mutex",
    "cron",
    "webhook",
    "pipeline",
    "protocol",
    "endpoint",
    "payload",
    "namespace",
    "instance",
    "container",
    "cluster",
    "registry",
    "proxy",
    "gateway",
    "runtime",
    "compiler",
    "debugger",
    "spreadsheet",
    "invoice",
    "deadline",
    "standup",
    "backlog",
    "ticket",
    "milestone",
    "stakeholder",
    "deployment",
    "outage",
    "rollback",
    "hotfix",
    "sprint",
    "retro",
    "roadmap",
    "handover",
    "escalation",
    "pivot",
];

#[cfg(test)]
mod tests {
    use super::*;

    /// The golden vectors Android checks against iOS (`DisplayNameGeneratorTest.kt`): if one
    /// breaks, this client names a person differently from the phone.
    #[test]
    fn names_match_ios_and_android() {
        for (id, name) in [
            ("550e8400-e29b-41d4-a716-446655440000", "cool cobra"),
            ("14f28d31-0000-0000-0000-000000000000", "silver raven"),
            ("test", "ancient sphinx"),
            ("construct", "idle deer"),
            ("6f5e37ac9b2d4e1f8a0c5d6e7f80911a", "gleaming serpent"),
        ] {
            assert_eq!(generated(id), name, "{id}");
        }
    }

    #[test]
    fn a_generated_name_stands_for_no_name() {
        let id = "550e8400-e29b-41d4-a716-446655440000";
        assert_eq!(resolved("Анна", "anna_k", id), "Анна");
        assert_eq!(
            resolved("Cool Cobra", "anna_k", id),
            "anna_k",
            "Android's case"
        );
        assert_eq!(resolved("", "", id), "cool cobra");
    }
}
