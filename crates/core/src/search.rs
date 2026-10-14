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
        }
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
