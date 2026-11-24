use std::fs;
use std::io;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

pub const LABEL: &str = "com.alecuba16.rust-vmnet-proxy";

fn home() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_default())
}

pub fn install_bin() -> PathBuf {
    home().join(".local/bin/rust-vmnet-proxy")
}

pub fn plist_path() -> PathBuf {
    home().join(format!("Library/LaunchAgents/{LABEL}.plist"))
}

pub fn log_dir() -> PathBuf {
    home().join("Library/Logs/rust-vmnet-proxy")
}

/// Whether the rust-vmnet-proxy brew formula is installed. With brew, service
/// verbs delegate to `brew services` (brew owns its own plist/label);
/// without it, the private LaunchAgent layout below is used.
fn brew_formula_present() -> bool {
    if let Ok(cellar) = std::env::var("RUST_VMNET_PROXY_BREW_CELLAR") {
        if !cellar.is_empty() {
            return Path::new(&cellar).exists();
        }
    }
    Path::new("/opt/homebrew/Cellar/rust-vmnet-proxy").exists()
        || Path::new("/usr/local/Cellar/rust-vmnet-proxy").exists()
}

fn brew_path() -> &'static str {
    ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"]
        .into_iter()
        .find(|p| Path::new(p).exists())
        .unwrap_or("brew")
}

fn brew_services(verb: &str) -> io::Result<()> {
    let status = Command::new(brew_path())
        .args(["services", verb, "rust-vmnet-proxy"])
        .status()?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "brew services {verb} rust-vmnet-proxy failed with {status}"
        )));
    }
    Ok(())
}

fn uid() -> String {
    unsafe { libc::getuid().to_string() }
}

fn service_target() -> String {
    format!("gui/{}/{}", uid(), LABEL)
}

fn launchctl(args: &[&str]) -> io::Result<()> {
    let status = Command::new("launchctl").args(args).status()?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "launchctl {} failed with {status}",
            args.join(" ")
        )));
    }
    Ok(())
}

fn launchctl_quiet(args: &[&str]) {
    let _ = Command::new("launchctl").args(args).status();
}

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

fn plist_xml(bin: &str, config_path: &str, log_file: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{bin}</string>
        <string>--config</string>
        <string>{config_path}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>EnvironmentVariables</key>
    <dict>
        <key>RUST_LOG</key>
        <string>info</string>
    </dict>
    <key>StandardOutPath</key>
    <string>{log_file}</string>
    <key>StandardErrorPath</key>
    <string>{log_file}</string>
    <key>ProcessType</key>
    <string>Background</string>
</dict>
</plist>
"#
    )
}

/// Copy the running exe to dst. In-place open+write when dst exists so the
/// file identity (inode) is preserved; plain copy when dst is missing.
/// The service is booted out first, so nothing executes the file mid-copy.
fn copy_current_exe(dst: &Path) -> io::Result<()> {
    let src = std::env::current_exe()?;
    let mut bytes = Vec::new();
    fs::File::open(&src)?.read_to_end(&mut bytes)?;
    if dst.exists() {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(dst)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
    } else {
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut f = fs::File::create(dst)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
    }
    Ok(())
}

pub fn install_macos() -> io::Result<()> {
    if brew_formula_present() {
        println!("brew install detected: managing {LABEL} via brew services");
        brew_services("start")?;
        println!("Started {LABEL} via brew services");
        return Ok(());
    }
    write_agent("install-mac")
}

pub fn update_macos() -> io::Result<()> {
    if brew_formula_present() {
        println!("brew install detected: restarting {LABEL} via brew services");
        brew_services("restart")?;
        println!("Restarted {LABEL} on the upgraded keg");
        return Ok(());
    }
    write_agent("update-mac")
}

fn write_agent(verb: &str) -> io::Result<()> {
    let bin = install_bin();
    let plist = plist_path();
    let service = service_target();
    println!("{verb}: installing {LABEL} to {}", bin.display());

    // Stop before touching the binary: an in-place refresh of a running
    // executable corrupts its image.
    println!("{verb}: booting out {service}");
    launchctl_quiet(&["bootout", &service]);

    println!("{verb}: copying binary to {}", bin.display());
    copy_current_exe(&bin)?;

    println!("{verb}: adhoc codesign");
    let _ = Command::new("codesign")
        .args(["-f", "-s", "-", &bin.display().to_string()])
        .status();

    fs::create_dir_all(log_dir())?;
    if let Some(parent) = plist.parent() {
        fs::create_dir_all(parent)?;
    }

    let config_path = home().join(".config/rust-vmnet-proxy/config.yaml");
    let log_file = log_dir().join("rust-vmnet-proxy.log");
    let xml = plist_xml(
        &xml_escape(&bin.display().to_string()),
        &xml_escape(&config_path.display().to_string()),
        &xml_escape(&log_file.display().to_string()),
    );
    println!("{verb}: writing plist {}", plist.display());
    fs::write(&plist, xml)?;

    println!("{verb}: bootstrap gui/{}", uid());
    launchctl_quiet(&[
        "bootstrap",
        &format!("gui/{}", uid()),
        &plist.display().to_string(),
    ]);
    println!("{verb}: kickstart -k {service}");
    launchctl(&["kickstart", "-k", &service])?;
    println!("{verb}: done");
    Ok(())
}

pub fn uninstall_macos() -> io::Result<()> {
    if brew_formula_present() {
        brew_services("stop")?;
        println!("Stopped {LABEL}; run `brew uninstall rust-vmnet-proxy` to remove the formula");
        return Ok(());
    }
    let service = service_target();
    println!("uninstall-mac: booting out {service}");
    launchctl_quiet(&["bootout", &service]);
    let plist = plist_path();
    println!("uninstall-mac: removing {}", plist.display());
    let _ = fs::remove_file(&plist);
    let bin = install_bin();
    println!("uninstall-mac: removing {}", bin.display());
    let _ = fs::remove_file(&bin);
    println!("uninstall-mac: config and logs are kept");
    Ok(())
}

pub fn start_macos() -> io::Result<()> {
    if brew_formula_present() {
        brew_services("start")?;
        println!("Started {LABEL} via brew services");
        return Ok(());
    }
    let plist = plist_path();
    if !plist.exists() {
        return Err(io::Error::other(format!(
            "no LaunchAgent plist at {}, run install-mac first",
            plist.display()
        )));
    }
    let service = service_target();
    println!("start-mac: bootstrap gui/{}", uid());
    launchctl_quiet(&[
        "bootstrap",
        &format!("gui/{}", uid()),
        &plist.display().to_string(),
    ]);
    println!("start-mac: kickstart -k {service}");
    launchctl(&["kickstart", "-k", &service])?;
    println!("Started {LABEL}");
    Ok(())
}

pub fn stop_macos() -> io::Result<()> {
    if brew_formula_present() {
        brew_services("stop")?;
        println!("Stopped {LABEL} via brew services");
        return Ok(());
    }
    let service = service_target();
    println!("stop-mac: booting out {service}");
    launchctl_quiet(&["bootout", &service]);
    println!("Stopped {LABEL}");
    Ok(())
}

pub fn restart_macos() -> io::Result<()> {
    if brew_formula_present() {
        brew_services("restart")?;
        println!("Restarted {LABEL} via brew services");
        return Ok(());
    }
    stop_macos()?;
    start_macos()?;
    println!("Restarted {LABEL}");
    Ok(())
}
