//! Ranking items for what the user typed. Only what a [`Summary`] shows is
//! searched (title, website hosts, username, tags, apps, folder): never a
//! password or a note. Every word typed must match something.

use crate::item::Summary;

/// The host of a website, lower case ("https://Mail.Example.org/x" →
/// "mail.example.org"); text without a scheme is taken as a host.
pub fn host(url: &str) -> String {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let rest = rest.rsplit_once('@').map(|(_, r)| r).unwrap_or(rest);
    let end = rest.find(['/', '?', '#', ':']).unwrap_or(rest.len());
    rest[..end].trim().to_lowercase()
}

fn word_score(s: &Summary, word: &str) -> u32 {
    let title = s.title.to_lowercase();
    let mut best = if title == word {
        100
    } else if title.starts_with(word) {
        80
    } else if title
        .split(|c: char| !c.is_alphanumeric())
        .any(|w| w.starts_with(word))
    {
        70
    } else if title.contains(word) {
        60
    } else {
        0
    };
    if s.websites.iter().any(|w| host(w).contains(word)) {
        best = best.max(50);
    }
    if s.username.to_lowercase().contains(word) {
        best = best.max(40);
    }
    let in_labels = s
        .tags
        .iter()
        .chain(&s.apps)
        .chain(std::iter::once(&s.folder))
        .any(|t| t.to_lowercase().contains(word));
    if in_labels {
        best = best.max(30);
    }
    best
}

/// Items matching every word of `query`, best first, then by title. An
/// empty query returns everything by title.
pub fn rank<'a>(items: impl IntoIterator<Item = &'a Summary>, query: &str) -> Vec<&'a Summary> {
    let words: Vec<String> = query.split_whitespace().map(str::to_lowercase).collect();
    let mut hits: Vec<(u32, &Summary)> = items
        .into_iter()
        .filter_map(|s| {
            let mut total = 0;
            for w in &words {
                match word_score(s, w) {
                    0 => return None,
                    n => total += n,
                }
            }
            Some((total, s))
        })
        .collect();
    hits.sort_by(|(a, x), (b, y)| {
        b.cmp(a)
            .then_with(|| x.title.to_lowercase().cmp(&y.title.to_lowercase()))
    });
    hits.into_iter().map(|(_, s)| s).collect()
}

/// One login for the fill picker, with why it ranks where it does.
pub struct Match<'a> {
    pub item: &'a Summary,
    pub score: u32,
    pub reason: &'static str,
}

/// A website's host without `www.`, and its name ("https://www.discord.com/x"
/// → ("discord.com", "discord"); "bank.co.uk" → "bank").
pub fn host_name(url: &str) -> (String, String) {
    let mut h = host(url);
    if let Some(rest) = h.strip_prefix("www.") {
        h = rest.to_string();
    }
    let parts: Vec<&str> = h.split('.').collect();
    let n = parts.len();
    let name = if n >= 3
        && ["co", "com", "org", "net", "ac", "gov"].contains(&parts[n - 2])
        && parts[n - 1].len() == 2
    {
        parts[n - 3]
    } else if n >= 2 {
        parts[n - 2]
    } else {
        parts[0]
    };
    let name = name.to_string();
    (h, name)
}

/// The fill picker's ranking (the Passwords plugin's own scoring, moved into
/// Safe): logins for the focused window (`class`, `title`) or a page (`url`),
/// best first, then by title. A login nothing points at stays with score 0,
/// so the picker's search still finds it. `query` keeps only logins whose
/// title, username or host contain it. Notes are never candidates.
pub fn match_logins<'a>(
    items: impl IntoIterator<Item = &'a Summary>,
    class: &str,
    title: &str,
    url: &str,
    query: &str,
) -> Vec<Match<'a>> {
    let wc = class.trim().to_lowercase();
    let wt = title.trim().to_lowercase();
    let q = query.trim().to_lowercase();
    let page = if url.trim().is_empty() {
        String::new()
    } else {
        host_name(url).0
    };
    let both = format!("{wc} {wt}");
    let words: Vec<&str> = both
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| w.len() >= 4 && !["window", "login", "sign"].contains(w))
        .collect();
    let mut out: Vec<Match<'a>> = Vec::new();
    for s in items {
        if s.kind != crate::item::Kind::Login {
            continue;
        }
        let tl = s.title.to_lowercase();
        let (mut score, mut reason) = (0u32, "");
        let mut bump = |n: u32, why: &'static str| {
            if n > score {
                score = n;
                reason = why;
            }
        };
        if !wc.is_empty() && s.apps.iter().any(|a| a.to_lowercase() == wc) {
            bump(50, "pinned to this app");
        }
        let mut first_host = String::new();
        for w in &s.websites {
            let (h, name) = host_name(w);
            if first_host.is_empty() {
                first_host = h.clone();
            }
            if !page.is_empty() && !h.is_empty() {
                if h == page {
                    bump(60, "same site");
                } else if page.ends_with(&format!(".{h}")) || h.ends_with(&format!(".{page}")) {
                    bump(45, "same site family");
                }
            }
            if name.len() >= 3 {
                if !wc.is_empty() && wc.contains(&name) {
                    bump(30, "site matches the app");
                } else if !wt.is_empty() && wt.contains(&name) {
                    bump(20, "site matches the window title");
                }
            }
        }
        if wc.len() >= 3 && !tl.is_empty() && (tl.contains(&wc) || wc.contains(&tl)) {
            bump(25, "title matches the app");
        } else if !tl.is_empty() && words.iter().any(|w| tl.contains(w)) {
            bump(10, "title matches the window");
        }
        if !q.is_empty() {
            let hay = format!("{tl} {} {first_host}", s.username.to_lowercase());
            if !hay.contains(&q) {
                continue;
            }
            score += 5;
        }
        out.push(Match {
            item: s,
            score,
            reason,
        });
    }
    out.sort_by(|a, b| {
        b.score.cmp(&a.score).then_with(|| {
            a.item
                .title
                .to_lowercase()
                .cmp(&b.item.title.to_lowercase())
        })
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::Kind;

    fn item(title: &str, user: &str, site: &str, tags: &[&str]) -> Summary {
        Summary {
            id: title.into(),
            kind: Kind::Login,
            title: title.into(),
            username: user.into(),
            websites: if site.is_empty() {
                vec![]
            } else {
                vec![site.into()]
            },
            apps: vec![],
            tags: tags.iter().map(|t| t.to_string()).collect(),
            folder: String::new(),
            has_password: true,
            has_otp: false,
            modified: None,
            ssh: None,
        }
    }

    fn app(mut s: Summary, class: &str) -> Summary {
        s.apps.push(class.into());
        s
    }

    fn picked<'a>(m: &'a [Match<'a>]) -> Vec<(&'a str, u32)> {
        m.iter().map(|m| (m.item.title.as_str(), m.score)).collect()
    }

    #[test]
    fn host_names() {
        assert_eq!(
            host_name("https://www.discord.com/login"),
            ("discord.com".into(), "discord".into())
        );
        assert_eq!(
            host_name("bank.co.uk"),
            ("bank.co.uk".into(), "bank".into())
        );
        assert_eq!(
            host_name("localhost"),
            ("localhost".into(), "localhost".into())
        );
    }

    #[test]
    fn the_picker_ranks_pins_then_sites_then_titles() {
        let all = [
            item("Zoom", "z", "", &[]),
            app(item("Work chat", "w", "", &[]), "discord"),
            item("Discord", "d", "https://discord.com", &[]),
            item("Other", "o", "https://example.org", &[]),
        ];
        let m = match_logins(&all, "discord", "Discord - General", "", "");
        assert_eq!(
            picked(&m),
            vec![
                ("Work chat", 50),
                ("Discord", 30),
                ("Other", 0),
                ("Zoom", 0)
            ]
        );
        assert_eq!(m[0].reason, "pinned to this app");
    }

    #[test]
    fn a_page_matches_its_site_and_the_query_filters() {
        let all = [
            item("GitHub", "sam", "https://github.com", &[]),
            item("GitHub Enterprise", "sam", "https://git.work.example", &[]),
            item("Docs", "sam", "https://docs.github.com", &[]),
        ];
        let m = match_logins(&all, "", "", "https://github.com/login", "");
        assert_eq!(picked(&m)[0], ("GitHub", 60));
        assert_eq!(picked(&m)[1], ("Docs", 45));
        let m = match_logins(&all, "", "", "", "enterprise");
        assert_eq!(picked(&m), vec![("GitHub Enterprise", 5)]);
    }

    #[test]
    fn notes_are_never_candidates() {
        let mut note = item("Discord recovery codes", "", "", &[]);
        note.kind = Kind::Note;
        assert!(match_logins(&[note], "discord", "", "", "").is_empty());
    }

    #[test]
    fn hosts() {
        assert_eq!(
            host("https://Mail.Example.org/inbox?x=1"),
            "mail.example.org"
        );
        assert_eq!(
            host("https://user:pw@git.example.com:8443/"),
            "git.example.com"
        );
        assert_eq!(host("bank.example"), "bank.example");
        assert_eq!(host("androidapp://com.bank.app"), "com.bank.app");
    }

    #[test]
    fn title_beats_host_beats_username() {
        let all = [
            item("Mail", "x", "https://other.example", &[]),
            item("Bank", "mailer", "", &[]),
            item("Work", "y", "https://mail.work.example", &[]),
            item("Gmail", "z", "", &[]),
        ];
        let got: Vec<&str> = rank(&all, "mail")
            .iter()
            .map(|s| s.title.as_str())
            .collect();
        assert_eq!(got, vec!["Mail", "Gmail", "Work", "Bank"]);
    }

    #[test]
    fn every_word_must_match() {
        let all = [
            item("GitHub", "sam", "https://github.com", &["work"]),
            item("GitHub", "sam-home", "https://github.com", &["home"]),
        ];
        let got = rank(&all, "github work");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].username, "sam");
        assert!(rank(&all, "github nothing").is_empty());
    }

    #[test]
    fn empty_query_lists_everything_by_title() {
        let all = [item("b", "", "", &[]), item("A", "", "", &[])];
        let got: Vec<&str> = rank(&all, "  ").iter().map(|s| s.title.as_str()).collect();
        assert_eq!(got, vec!["A", "b"]);
    }
}
