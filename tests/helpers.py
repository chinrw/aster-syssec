from __future__ import annotations

import json
import subprocess
from pathlib import Path


def write_fixture(root: Path) -> Path:
    files = {
        "rust-toolchain.toml": """[toolchain]\nchannel = \"nightly-test\"\n""",
        "kernel/core/src/syscall/mod.rs": """
mod read;
mod recvmsg;
mod missing;
""",
        "kernel/core/src/syscall/arch/x86.rs": """
impl_syscall_nums_and_dispatch_fn! {
    SYS_READ = 0 => sys_read(args[..3]);
    SYS_RECVMSG = 47 => sys_recvmsg(args[..3]);
    SYS_MISSING = 99 => sys_missing(args[..1]);
}
""",
        "kernel/core/src/syscall/arch/riscv.rs": """
#[path = \"./generic.rs\"]
mod generic;
generic::define_syscalls_with_generic_syscall_table! {}
""",
        "kernel/core/src/syscall/arch/loongarch.rs": """
#[path = \"./generic.rs\"]
mod generic;
generic::define_syscalls_with_generic_syscall_table! {}
""",
        "kernel/core/src/syscall/arch/generic.rs": """
macro_rules! define_syscalls_with_generic_syscall_table {
    () => {
        impl_syscall_nums_and_dispatch_fn! {
            SYS_READ = 63 => sys_read(args[..3]);
            SYS_RECVMSG = 212 => sys_recvmsg(args[..3]);
        }
    }
}
""",
        "kernel/core/src/syscall/read.rs": """
pub(super) fn sys_read(
    raw_fd: i32,
    user_buf_addr: Vaddr,
    buf_len: usize,
    ctx: &Context,
) -> Result<SyscallReturn> {
    // from_bits_truncate here must not be scanned.
    let message = \"panic! and from_bits_truncate\";
    let writer = ctx.user_space().writer(user_buf_addr, buf_len)?;
    file.read(writer)
}

fn selected_but_not_proven_reachable(flags: i32) {
    let _flags = Flags::from_bits_truncate(flags);
}
""",
        "kernel/core/src/syscall/recvmsg.rs": """
pub(super) fn sys_recvmsg(
    sockfd: i32,
    user_msghdr_ptr: Vaddr,
    flags: i32,
    ctx: &Context,
) -> Result<SyscallReturn> {
    let user_space = ctx.user_space();
    let mut header: CUserMsgHdr = user_space.read_val(user_msghdr_ptr)?;
    let flags = RecvFlags::from_bits_truncate(flags);
    let output = socket.recvmsg(&mut writer, flags)?;
    user_space.write_val(user_msghdr_ptr, &header)?;
    Ok(output.len())
}
""",
        "book/src/kernel/linux-compatibility/syscall-flag-coverage/io.scml": """
read(fd, buf, count);
recvmsg(fd, msg, flags);
orphan_scml(value);
""",
        "test/initramfs/src/regression/io/read.c": """
#include <unistd.h>
int main(void) { return read(0, 0, 0); }
""",
        ".agents/skills/aster-code-review/SKILL.md": """
---
name: aster-code-review
---
Review files or a diff.
""",
        ".agents/skills/aster-code-review/aster_code_review.sh": """
#!/bin/sh
exit 0
""",
        ".agents/skills/aster-code-review/agent_profiles/codex/profile.json": """
{"command": ["codex", "exec", "{prompt}"]}
""",
    }
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content.lstrip(), encoding="utf-8")
        if path.name == "aster_code_review.sh":
            path.chmod(0o755)
    return root


def write_specula_inputs(root: Path) -> tuple[Path, Path]:
    profile = root / "profile"
    specula = root / "Specula"
    profile.mkdir(parents=True, exist_ok=True)
    specula.mkdir(parents=True, exist_ok=True)
    (specula / "pyproject.toml").write_text(
        '[project]\nname = "specula-fixture"\n', encoding="utf-8"
    )
    config = {
        "version": 1,
        "default_profile": "review",
        "profiles": {"review": {"agent": "codex", "model": "fixture", "effort": "low"}},
        "phases": {"review": "review"},
    }
    (profile / "specula-asterinas-hybrid.json").write_text(
        json.dumps(config),
        encoding="utf-8",
    )
    guidance = profile / "guidance/06-socket-ancillary-data.md"
    guidance.parent.mkdir(parents=True, exist_ok=True)
    guidance.write_text(
        "# Goal\n\nReview one socket commit protocol.\n", encoding="utf-8"
    )
    return profile, specula


def init_git_repository(root: Path) -> str:
    subprocess.run(
        ["git", "init", "-b", "main"], cwd=root, check=True, capture_output=True
    )
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=root, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"], cwd=root, check=True
    )
    subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=root, check=True)
    subprocess.run(["git", "add", "."], cwd=root, check=True)
    subprocess.run(
        ["git", "commit", "-m", "fixture"], cwd=root, check=True, capture_output=True
    )
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
