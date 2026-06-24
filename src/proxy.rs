use serde_json::Value;
use std::process::Command;

const BIN: &str = "/usr/local/sbin/akurai-mail-server";

pub fn exec(args: &[&str]) -> Result<Value, String> {
    let mut cmd = Command::new("sudo");
    cmd.arg(BIN);
    for arg in args {
        cmd.arg(arg);
    }

    let output = cmd.output().map_err(|e| format!("exec failed: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("command failed: {stderr}"));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&stdout).map_err(|e| format!("invalid JSON: {e}"))
}
