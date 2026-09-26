//! Synthetic person names for generated tenants (spec Addendum B.4): common, generic,
//! ASCII-only given names and surnames, drawn deterministically from an `Rng`. No name here is
//! taken from, or matched against, any real capture.

use crate::rng::Rng;

/// 64 common, generic, ASCII-only given names.
pub const FIRST_NAMES: [&str; 64] = [
    "Avery", "Blake", "Casey", "Dana", "Elliot", "Frankie", "Gale", "Harper", "Iris", "Jordan",
    "Kelly", "Logan", "Morgan", "Noel", "Oakley", "Parker", "Quinn", "Reese", "Sage", "Taylor",
    "Val", "Wren", "Alex", "Bailey", "Cameron", "Drew", "Emerson", "Finley", "Gray", "Hayden",
    "Indigo", "Jamie", "Kai", "Lane", "Marlowe", "Nova", "Ocean", "Peyton", "Rowan", "Skyler",
    "Toby", "Uma", "Vance", "Winter", "Xander", "Yael", "Zion", "Adrian", "Bryce", "Cody", "Devon",
    "Ellis", "Frances", "Greer", "Hollis", "Ira", "Jesse", "Kendall", "Lennox", "Mason", "Nico",
    "Ollie", "Presley", "Rene",
];

/// 64 common, generic, ASCII-only surnames.
pub const LAST_NAMES: [&str; 64] = [
    "Adams",
    "Baker",
    "Carter",
    "Diaz",
    "Evans",
    "Foster",
    "Grant",
    "Hayes",
    "Irwin",
    "Jensen",
    "King",
    "Lewis",
    "Moore",
    "Nelson",
    "Ortiz",
    "Parks",
    "Reed",
    "Simmons",
    "Tucker",
    "Underwood",
    "Vaughn",
    "Walsh",
    "Young",
    "Bennett",
    "Cole",
    "Dawson",
    "Ferris",
    "Graham",
    "Holt",
    "Ingram",
    "James",
    "Keller",
    "Lambert",
    "Mercer",
    "Norris",
    "Osborn",
    "Porter",
    "Quincy",
    "Rhodes",
    "Sanders",
    "Trent",
    "Upton",
    "Vincent",
    "Ward",
    "Sawyer",
    "Yates",
    "Zane",
    "Archer",
    "Bishop",
    "Chambers",
    "Dunbar",
    "Emery",
    "Fletcher",
    "Gibbs",
    "Howell",
    "Ibarra",
    "Jacoby",
    "Knox",
    "Lowery",
    "Mathis",
    "Nash",
    "Odom",
    "Prescott",
    "Rourke",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Person {
    pub first: String,
    pub last: String,
    /// `first.last`, lower-case ASCII; unique within one `people` call (repeats get 2, 3, …).
    pub alias: String,
}

/// `n` people drawn from the name lists.
pub fn people(rng: &mut Rng, n: usize) -> Vec<Person> {
    let mut used = std::collections::BTreeMap::<String, u32>::new();
    (0..n)
        .map(|_| {
            let first = rng.pick(&FIRST_NAMES).to_string();
            let last = rng.pick(&LAST_NAMES).to_string();
            let base = format!(
                "{}.{}",
                first.to_ascii_lowercase(),
                last.to_ascii_lowercase()
            );
            let count = used.entry(base.clone()).or_insert(0);
            *count += 1;
            let alias = if *count == 1 {
                base
            } else {
                format!("{base}{count}")
            };
            Person { first, last, alias }
        })
        .collect()
}
