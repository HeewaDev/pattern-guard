//! A fake, read-only file system for the download endpoint and the simulated shell.
//! Nothing touches the real disk.

/// Marker in the fake `/etc/passwd` (path traversal / command injection read it).
pub const PASSWD_MARKER: &str = "root:x:0:0:root:/root:/bin/bash";
/// Marker in the fake `/proc/self/environ`.
pub const ENVIRON_MARKER: &str = "DB_PASSWORD=pg-demo-Xq81";

const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\npostgres:x:105:111:PostgreSQL administrator:/var/lib/postgresql:/bin/bash\n";

const DIRS: &[&str] = &[
    "/",
    "/bin",
    "/etc",
    "/home",
    "/proc",
    "/proc/self",
    "/root",
    "/srv",
    "/srv/app",
    "/srv/app/config",
    "/srv/app/files",
    "/tmp",
    "/usr",
    "/usr/bin",
    "/var",
    "/var/www",
];

/// (path, content, readable by www-data)
const FILES: &[(&str, &str, bool)] = &[
    ("/etc/passwd", PASSWD, true),
    ("/etc/shadow", "root:$6$x:19000:0:99999:7:::\n", false),
    ("/etc/hostname", "demo-shop\n", true),
    (
        "/etc/hosts",
        "127.0.0.1 localhost\n127.0.1.1 demo-shop\n",
        true,
    ),
    (
        "/proc/self/environ",
        "PATH=/usr/bin:/bin\0APP_ENV=production\0DB_PASSWORD=pg-demo-Xq81\0",
        true,
    ),
    ("/root/.bash_history", "ls\n", false),
    (
        "/srv/app/config/app.ini",
        "[db]\nhost = 127.0.0.1\nuser = shop\n",
        true,
    ),
    (
        "/srv/app/files/report.pdf",
        "%PDF-1.4\n% quarterly report (demo)\n",
        true,
    ),
    (
        "/srv/app/files/price-list.csv",
        "id,name,price\n1,Espresso cup,9.50\n",
        true,
    ),
    ("/bin/cat", "\x7fELF", true),
    ("/bin/echo", "\x7fELF", true),
    ("/bin/ls", "\x7fELF", true),
    ("/bin/ping", "\x7fELF", true),
    ("/bin/sh", "\x7fELF", true),
    ("/bin/sleep", "\x7fELF", true),
    ("/bin/uname", "\x7fELF", true),
    ("/usr/bin/head", "\x7fELF", true),
    ("/usr/bin/id", "\x7fELF", true),
    ("/usr/bin/whoami", "\x7fELF", true),
];

/// Why opening a path failed, as the C library would say it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsError {
    NotFound,
    PermissionDenied,
    IsADirectory,
    NotADirectory,
}

impl FsError {
    pub fn message(self) -> &'static str {
        match self {
            FsError::NotFound => "No such file or directory",
            FsError::PermissionDenied => "Permission denied",
            FsError::IsADirectory => "Is a directory",
            FsError::NotADirectory => "Not a directory",
        }
    }
}

pub fn is_dir(path: &str) -> bool {
    DIRS.contains(&path)
}

fn file(path: &str) -> Option<(&'static str, bool)> {
    FILES
        .iter()
        .find(|(p, _, _)| *p == path)
        .map(|(_, c, r)| (*c, *r))
}

/// Resolves `path` like the kernel's path walk: relative to `cwd`, `.` and empty
/// components skipped, `..` goes up (never above `/`), and every component before the
/// last must be an existing directory (so `nonexistent/../x` fails, as on Linux).
/// Returns the canonical absolute path.
pub fn resolve(cwd: &str, path: &str) -> Result<String, FsError> {
    if path.is_empty() {
        return Err(FsError::NotFound);
    }
    let mut parts: Vec<&str> = Vec::new();
    if !path.starts_with('/') {
        parts.extend(cwd.split('/').filter(|c| !c.is_empty()));
    }
    let comps: Vec<&str> = path.split('/').collect();
    for (i, c) in comps.iter().enumerate() {
        let last = i + 1 == comps.len();
        match *c {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            name => {
                parts.push(name);
                let here = format!("/{}", parts.join("/"));
                if !last && !is_dir(&here) {
                    // a component in the middle must be a directory
                    return Err(if file(&here).is_some() {
                        FsError::NotADirectory
                    } else {
                        FsError::NotFound
                    });
                }
            }
        }
    }
    Ok(format!("/{}", parts.join("/")))
}

/// Reads a file as www-data.
pub fn read(cwd: &str, path: &str) -> Result<&'static str, FsError> {
    let abs = resolve(cwd, path)?;
    if is_dir(&abs) {
        return Err(FsError::IsADirectory);
    }
    match file(&abs) {
        Some((content, true)) => Ok(content),
        Some((_, false)) => Err(FsError::PermissionDenied),
        None => Err(FsError::NotFound),
    }
}

/// Names in a directory (sorted).
pub fn list(dir: &str) -> Vec<String> {
    let prefix = if dir == "/" {
        "/".to_string()
    } else {
        format!("{dir}/")
    };
    let mut out: Vec<String> = DIRS
        .iter()
        .copied()
        .chain(FILES.iter().map(|(p, _, _)| *p))
        .filter_map(|p| p.strip_prefix(prefix.as_str()))
        .filter(|rest| !rest.is_empty() && !rest.contains('/'))
        .map(str::to_string)
        .collect();
    out.sort();
    out
}

/// Every path (directories and files), for glob expansion.
pub fn all_paths() -> impl Iterator<Item = &'static str> {
    DIRS.iter().copied().chain(FILES.iter().map(|(p, _, _)| *p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traversal_resolves_like_linux() {
        let base = "/srv/app/files";
        assert!(read(base, "report.pdf").unwrap().starts_with("%PDF"));
        assert!(
            read(base, "../../../etc/passwd")
                .unwrap()
                .contains(PASSWD_MARKER)
        );
        assert!(
            read(base, "../../../../../../etc/passwd").is_ok(),
            "stops at /"
        );
        assert!(read(base, ".././../..//etc/./passwd").is_ok());
        assert_eq!(
            read(base, "nope/../../../../etc/passwd"),
            Err(FsError::NotFound),
            "a missing directory can't be walked through"
        );
        assert_eq!(read(base, "....//....//etc/passwd"), Err(FsError::NotFound));
        assert_eq!(read(base, "..\\..\\etc\\passwd"), Err(FsError::NotFound));
        assert_eq!(
            read(base, "../../../etc/shadow"),
            Err(FsError::PermissionDenied)
        );
        assert_eq!(read(base, "../../../etc"), Err(FsError::IsADirectory));
        assert_eq!(read(base, "report.pdf/x"), Err(FsError::NotADirectory));
    }

    #[test]
    fn listing() {
        assert!(list("/").contains(&"etc".to_string()));
        assert_eq!(list("/srv/app/files"), ["price-list.csv", "report.pdf"]);
    }
}
