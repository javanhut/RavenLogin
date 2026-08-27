//! `/etc/passwd`: which accounts exist, and which of them are people.
//!
//! Parsed directly rather than through `getpwnam`, for the same reason
//! `raven-init` does it: glibc's NSS `dlopen`s a backend named in
//! `nsswitch.conf`, and a login screen that hangs because it tried to load an
//! `ldap` module that is not installed is a login screen nobody can log in to
//! in order to fix. RavenLinux ships `passwd: files` and has no name service,
//! so reading the file is not a shortcut past NSS — it *is* what NSS would do.

use std::fs;
use std::path::Path;

use crate::Error;

/// The uid at and above which an account is a person rather than a daemon.
///
/// Matches `UID_MIN` in `/etc/login.defs`, and `raven-init`'s constant of the
/// same name. If the three ever disagree, the greeter offers a different set
/// of accounts than init would autologin, which is the kind of difference
/// nobody notices until an account is missing from the list.
pub const FIRST_REGULAR_UID: u32 = 1000;

/// Accounts above this are not people either — `nobody` sits at 65534.
pub const LAST_REGULAR_UID: u32 = 60000;

/// Shells that mean "this account cannot have an interactive session".
///
/// Compared on the file name so that `/usr/bin/nologin` and `/sbin/nologin`
/// are both caught without listing every path a distro has ever used.
const NON_INTERACTIVE_SHELLS: &[&str] = &["nologin", "false", "sync", "shutdown", "halt"];

/// One account, resolved far enough to become a process's credentials and to
/// be drawn on a login screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    /// The GECOS field, whose first comma-separated part is the full name.
    pub gecos: String,
    pub home: String,
    pub shell: String,
    /// Supplementary groups, from every `/etc/group` line naming this user.
    pub groups: Vec<u32>,
}

impl Account {
    /// What to show a person on the login screen.
    ///
    /// The first comma-separated GECOS field is the full name; everything after
    /// it is office and phone numbers that `chfn` puts there, which nobody
    /// wants under their avatar. Falls back to the account name when GECOS is
    /// empty, which it usually is.
    #[must_use]
    pub fn display_name(&self) -> &str {
        let full_name = self.gecos.split(',').next().unwrap_or("").trim();
        if full_name.is_empty() {
            &self.name
        } else {
            full_name
        }
    }

    /// The letter to draw in the avatar circle when there is no avatar image.
    ///
    /// Uppercased from the display name; falls back to `?` for a name that
    /// starts with something that has no uppercase form, rather than drawing
    /// an empty circle.
    #[must_use]
    pub fn initial(&self) -> char {
        self.display_name()
            .chars()
            .find(|c| c.is_alphanumeric())
            .and_then(|c| c.to_uppercase().next())
            .unwrap_or('?')
    }

    /// Whether this account is a person who could sit down at the machine.
    ///
    /// Two conditions, and both are needed: the uid range excludes daemons and
    /// `nobody`, and the shell excludes accounts that exist for a service to
    /// own files as. An account with a real uid and `/usr/bin/nologin` is
    /// deliberately not a login, and offering it would produce a tile that can
    /// never succeed.
    #[must_use]
    pub fn is_person(&self) -> bool {
        if self.uid < FIRST_REGULAR_UID || self.uid > LAST_REGULAR_UID {
            return false;
        }
        let shell_name = self.shell.rsplit('/').next().unwrap_or(&self.shell);
        !NON_INTERACTIVE_SHELLS.contains(&shell_name)
    }
}

/// Read every account from a `/etc/passwd`-shaped file.
pub fn load(path: &Path) -> Result<Vec<Account>, Error> {
    let text = fs::read_to_string(path).map_err(|source| Error::Read {
        path: path.display().to_string(),
        source,
    })?;
    Ok(parse(&text))
}

/// Fill in supplementary groups from an `/etc/group`-shaped file.
///
/// A missing or unreadable group file is not an error: the account still has
/// its primary gid, which is enough to start a session. Losing `video` means a
/// desktop that cannot open the GPU, so this is logged rather than swallowed.
pub fn attach_groups(accounts: &mut [Account], path: &Path) {
    let Ok(text) = fs::read_to_string(path) else {
        tracing::warn!(
            path = %path.display(),
            "cannot read the group file; sessions will start with only their primary group"
        );
        return;
    };
    for account in accounts {
        account.groups = parse_groups(&text, &account.name, account.gid);
    }
}

/// Every account in the file, in file order, skipping lines that are not
/// accounts.
#[must_use]
pub fn parse(text: &str) -> Vec<Account> {
    text.lines().filter_map(parse_line).collect()
}

/// One `/etc/passwd` line: `name:passwd:uid:gid:gecos:home:shell`.
///
/// A short or non-numeric line is skipped rather than fatal. A damaged
/// `/etc/passwd` should cost you the accounts on the broken lines, not the
/// ability to log in as anybody.
fn parse_line(line: &str) -> Option<Account> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    let fields: Vec<&str> = line.split(':').collect();
    if fields.len() < 7 {
        return None;
    }

    Some(Account {
        name: fields[0].to_string(),
        uid: fields[2].parse().ok()?,
        gid: fields[3].parse().ok()?,
        gecos: fields[4].to_string(),
        home: fields[5].to_string(),
        shell: fields[6].to_string(),
        groups: Vec::new(),
    })
}

/// Every gid this user belongs to: the primary, plus each group listing them.
///
/// Sorted and deduplicated so the result does not depend on file order —
/// otherwise two machines with the same accounts hand their sessions
/// differently-ordered group lists, and the difference shows up only as a
/// permission that works on one and not the other.
fn parse_groups(text: &str, user: &str, primary_gid: u32) -> Vec<u32> {
    let mut gids = vec![primary_gid];

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 4 {
            continue;
        }
        let Ok(gid) = fields[2].parse::<u32>() else {
            continue;
        };
        // Exact match on each member: `javan` must not match `javanx`.
        if fields[3].split(',').any(|m| m.trim() == user) {
            gids.push(gid);
        }
    }

    gids.sort_unstable();
    gids.dedup();
    gids
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWD: &str = "\
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/:/usr/bin/nologin
javan:x:1000:1000:Javan Hutchinson,,,:/home/javan:/usr/bin/ravenshell
second:x:1001:1001::/home/second:/bin/sh
svc:x:1002:1002:A service:/var/lib/svc:/usr/bin/nologin
greeter:x:990:990:Raven greeter:/var/lib/raven-greeter:/usr/bin/nologin
nobody:x:65534:65534:Nobody:/:/usr/bin/nologin
";

    const GROUP: &str = "\
root:x:0:
wheel:x:10:javan
video:x:91:javan,second
audio:x:92:second
input:x:97:javan
javan:x:1000:
render:x:998:javan
";

    fn account(name: &str) -> Account {
        parse(PASSWD)
            .into_iter()
            .find(|a| a.name == name)
            .unwrap_or_else(|| panic!("{name} is in the fixture"))
    }

    #[test]
    fn parses_a_regular_account() {
        let a = account("javan");
        assert_eq!(a.uid, 1000);
        assert_eq!(a.gid, 1000);
        assert_eq!(a.home, "/home/javan");
        assert_eq!(a.shell, "/usr/bin/ravenshell");
    }

    #[test]
    fn short_and_comment_lines_are_skipped() {
        assert!(parse_line("broken:x:1000").is_none());
        assert!(parse_line("").is_none());
        assert!(parse_line("# a comment").is_none());
        assert!(parse_line("noname:x:notanumber:0:::/bin/sh").is_none());
    }

    /// Exactly the accounts a login screen should offer: not root, not
    /// daemons, not nologin shells.
    #[test]
    fn only_people_are_people() {
        let people: Vec<String> = parse(PASSWD)
            .into_iter()
            .filter(Account::is_person)
            .map(|a| a.name)
            .collect();
        assert_eq!(people, vec!["javan", "second"]);
    }

    /// The greeter's own account has a regular-looking uid in some layouts;
    /// its nologin shell is what keeps it off its own login screen.
    #[test]
    fn a_nologin_shell_is_not_a_person() {
        assert!(!account("svc").is_person());
        assert!(!account("greeter").is_person());
    }

    #[test]
    fn root_and_nobody_are_not_people() {
        assert!(!account("root").is_person());
        assert!(!account("nobody").is_person());
    }

    #[test]
    fn display_name_takes_only_the_first_gecos_field() {
        assert_eq!(account("javan").display_name(), "Javan Hutchinson");
    }

    #[test]
    fn display_name_falls_back_to_the_account_name() {
        assert_eq!(account("second").display_name(), "second");
    }

    #[test]
    fn initial_is_the_first_alphanumeric_uppercased() {
        assert_eq!(account("javan").initial(), 'J');
        assert_eq!(account("second").initial(), 'S');
    }

    #[test]
    fn groups_include_primary_and_memberships() {
        // wheel, video, input, javan(primary), render — sorted, deduped.
        assert_eq!(
            parse_groups(GROUP, "javan", 1000),
            vec![10, 91, 97, 998, 1000]
        );
    }

    #[test]
    fn primary_gid_is_not_duplicated() {
        assert_eq!(
            parse_groups("javan:x:1000:javan\n", "javan", 1000),
            vec![1000]
        );
    }

    #[test]
    fn membership_is_not_a_substring_match() {
        assert_eq!(
            parse_groups("other:x:50:javanx\n", "javan", 1000),
            vec![1000]
        );
    }
}
