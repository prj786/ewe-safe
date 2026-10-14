//! Seeded random interleavings: 2–3 machines add and edit items, go offline
//! and back, lock and unlock, and poll, in any order. At the end, all online:
//! every item anyone added is on every machine, every username anyone set is
//! there (current or in history), and the machines agree.
//!
//! `SAFE_SYNC_SEEDS=n` runs more seeds (default 25); `SAFE_SYNC_SALT` picks
//! another series.

mod common;

use std::collections::BTreeMap;

use common::*;
use safe_core::Safe;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

struct Node {
    m: Machine,
    safe: Option<Safe>,
}

fn run(seed: u64) {
    let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
    let mock = Mock::start();
    let d = scratch(&format!("interleave-{seed}"));
    let count = 2 + rng.below(2);

    let mut nodes: Vec<Node> = Vec::new();
    let mut first = machine(&mock, d.join("m0"), "m0");
    let mut s0 = new_safe();
    first.sync.create(&mut s0, &key()).expect("create");
    nodes.push(Node {
        m: first,
        safe: Some(s0),
    });
    for n in 1..count {
        let mut m = machine(&mock, d.join(format!("m{n}")), &format!("m{n}"));
        let (s, _) = m.sync.load(&key()).expect("load");
        nodes.push(Node { m, safe: Some(s) });
    }

    // title → every username it was given
    let mut versions: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut made = 0;
    let mut offline = vec![false; count];
    for _ in 0..40 {
        let i = rng.below(count);
        let node = &mut nodes[i];
        if node.safe.is_none() {
            // locked: unlock (offline it opens the cache) or poll locked
            if rng.below(2) == 0 {
                node.safe = Some(node.m.sync.load(&key()).expect("unlock").0);
            } else {
                node.m.sync.poll(None).expect("locked poll");
            }
            continue;
        }
        match rng.below(20) {
            0..=5 => {
                made += 1;
                let title = format!("s{seed}-m{i}-{made}");
                let user = format!("{title}-v0");
                let s = node.safe.as_mut().expect("unlocked");
                s.add(&login(&title, &user)).expect("add");
                node.m.sync.save(s, &key()).expect("save");
                versions.insert(title, vec![user]);
            }
            6..=10 => {
                let s = node.safe.as_mut().expect("unlocked");
                let mine: Vec<String> = s
                    .items()
                    .into_iter()
                    .map(|it| it.title)
                    .filter(|t| versions.get(t).is_some_and(|v| v.len() < 8))
                    .collect();
                if mine.is_empty() {
                    continue;
                }
                let title = mine[rng.below(mine.len())].clone();
                let v = versions.get_mut(&title).expect("known");
                let user = format!("{title}-v{}-m{i}", v.len());
                let id = id_of(s, &title);
                let mut draft = s.draft(&id).expect("draft");
                draft.username = user.clone();
                s.update(&id, &draft).expect("update");
                node.m.sync.save(s, &key()).expect("save");
                v.push(user);
            }
            11..=13 => {
                offline[i] = !offline[i];
                if offline[i] {
                    node.m.creds.offline();
                } else {
                    node.m.creds.online();
                }
            }
            14..=17 => {
                let s = node.safe.as_mut().expect("unlocked");
                node.m.sync.poll(Some((s, &key()))).expect("poll");
            }
            _ => node.safe = None,
        }
    }

    // everyone back online, unlocked, a few rounds of polling
    for node in nodes.iter_mut() {
        node.m.creds.online();
        if node.safe.is_none() {
            node.safe = Some(node.m.sync.load(&key()).expect("unlock").0);
        }
    }
    for _ in 0..4 {
        for node in nodes.iter_mut() {
            let s = node.safe.as_mut().expect("unlocked");
            node.m.sync.poll(Some((s, &key()))).expect("poll");
        }
    }

    let want: Vec<String> = versions.keys().cloned().collect();
    let mut current: Option<Vec<(String, String)>> = None;
    for (n, node) in nodes.iter().enumerate() {
        let s = node.safe.as_ref().expect("unlocked");
        assert_eq!(titles(s), want, "seed {seed}: machine {n} is missing items");
        assert!(
            !node.m.sync.status().pending,
            "seed {seed}: machine {n} still pending"
        );
        for (title, users) in &versions {
            let ever = usernames_ever(s, title);
            for u in users {
                assert!(
                    ever.contains(u),
                    "seed {seed}: machine {n} lost {u} of {title}"
                );
            }
        }
        let now: Vec<(String, String)> = want
            .iter()
            .map(|t| (t.clone(), username_of(s, t)))
            .collect();
        match &current {
            None => current = Some(now),
            Some(c) => assert_eq!(c, &now, "seed {seed}: machines {n} and 0 disagree"),
        }
    }
    let place = safe_core::Safe::open(&mock.file(FILE).expect("file"), &key()).expect("open");
    assert_eq!(
        titles(&place),
        want,
        "seed {seed}: the place is missing items"
    );
}

#[test]
fn random_interleavings_lose_nothing() {
    let seeds: u64 = std::env::var("SAFE_SYNC_SEEDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(25);
    let salt: u64 = std::env::var("SAFE_SYNC_SALT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    for n in 0..seeds {
        run(salt * 1_000_003 + n);
    }
}
