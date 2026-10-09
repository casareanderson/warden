"""The estate: what warden can reach, and how. One definition for scanning, patching,
integrity and hardening, so adding a box is a config edit.

warden.yml:
    hosts:
      - name: pve1
        kind: proxmox            # a Proxmox VE node, reached as root over SSH
        ssh: root@10.0.0.2
        discover: true           # every RUNNING LXC becomes a ct:<vmid> target
        docker_cts: [104]        # LXCs that run Docker → their images are scanned as img:ct104
        patch: true
      - name: nas
        kind: docker             # any box running Docker (user needs the docker group, not root)
        ssh: admin@10.0.0.5
        firmware: zimaos         # optional vendor-firmware check → fw:nas
      - name: appliance          # a Docker appliance OS with no sudo (ZimaOS, Unraid…) that should ALSO get
        kind: linux              #   integrity + hardening sweeps: host:<ip>, plus img:<name> and fw:<name>
        ssh: admin@10.0.0.7
        docker: true
        firmware: zimaos
        root_via: docker         # root = a throwaway `docker run --privileged … chroot /host` (estate.root_image)
        os_scan: false           # no dpkg/apk DB to scan; the firmware check covers the OS
      - name: llm
        kind: linux              # plain Debian/Ubuntu/Alpine box
        ssh: me@10.0.0.6
        sudo_secret: LLM_SUDO    # sudo -S password for patching (a secret name, never the value)
        patch: true
      - name: this-box
        kind: local              # the machine warden runs on, no SSH
    roles:                       # optional, shown to whoever approves a patch
      ct:100: "reverse proxy + this dashboard"
    core: [ct:100]               # restarts of these wait for the night window

Target ids are stable strings stored in the database:
    node:<ip>  ct:<vmid>  host:<ip>  host:local  img:<name>  img:ct<vmid>  fw:<name>  ctr:<img-host>:<container>
"""
import shutil
import subprocess

from . import config, secrets

SSH = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=10"]
KINDS = ("proxmox", "docker", "linux", "local")


def sh_quote(s):
    return "'" + s.replace("'", "'\"'\"'") + "'"


def _addr(ssh):
    return ssh.split("@", 1)[-1] if ssh else ""


def run(cmd, timeout=300, binary=False, inp=None):
    # never inherit stdin: ssh would swallow whatever the caller pipes in (a script, a heredoc)
    p = subprocess.run(cmd, capture_output=True, timeout=timeout, input=inp, text=not binary,
                       **({} if inp is not None else {"stdin": subprocess.DEVNULL}))
    return p.returncode, p.stdout, p.stderr


def declared():
    return [h for h in (config.get("hosts") or []) if isinstance(h, dict)]


def roles():
    return dict(config.get("roles") or {})


def core():
    return set(config.get("core") or [])


def self_target():
    """The box warden itself runs on — never patched by warden (it would kill the patcher mid-run)."""
    return config.get("estate.self_target") or ""


def targets(discover=True):
    """Every scannable thing. Proxmox nodes are asked for their running containers each call,
    so a new CT is picked up without a config change."""
    out = []
    for h in declared():
        kind, ssh, name = h.get("kind", "linux"), h.get("ssh", ""), h.get("name") or _addr(h.get("ssh"))
        patch = 1 if h.get("patch") else 0
        if kind == "proxmox":
            ip = _addr(ssh)
            out.append({"target": f"node:{ip}", "kind": "node", "name": name, "node": ip, "ssh": ssh,
                        "vmid": None, "patchable": patch})
            if discover and h.get("discover", True):
                rc, so, _ = run(SSH + [ssh, "pct list | tail -n +2"], timeout=60)
                for line in (so or "").splitlines():
                    f = line.split()
                    if len(f) >= 3 and f[1] == "running":
                        out.append({"target": f"ct:{f[0]}", "kind": "ct", "name": f[-1], "node": ip, "ssh": ssh,
                                    "vmid": int(f[0]), "patchable": patch})
            for vmid in h.get("docker_cts") or []:
                out.append({"target": f"img:ct{vmid}", "kind": "images", "name": f"CT{vmid} Docker images",
                            "node": ip, "ssh": ssh, "vmid": int(vmid), "patchable": 0})
        elif kind == "docker":
            out.append({"target": f"img:{name}", "kind": "images", "name": f"{name} Docker images", "node": None,
                        "ssh": ssh, "vmid": None, "patchable": 0})
        elif kind in ("linux", "local"):
            tid = "host:local" if kind == "local" else f"host:{_addr(ssh)}"
            out.append({"target": tid, "kind": "host" if kind == "linux" else "local", "name": name, "node": None,
                        "ssh": ssh, "vmid": None, "patchable": patch, "sudo_secret": h.get("sudo_secret"),
                        "root_via": h.get("root_via"), "os_scan": h.get("os_scan", True)})
            if h.get("docker"):
                out.append({"target": f"img:{name}", "kind": "images", "name": f"{name} Docker images",
                            "node": None, "ssh": ssh, "vmid": None, "patchable": 0, "local": kind == "local"})
        if h.get("firmware"):
            out.append({"target": f"fw:{name}", "kind": "firmware", "name": f"{name} ({h['firmware']})", "node": None,
                        "ssh": ssh, "vmid": None, "patchable": 0, "firmware": h["firmware"]})
    return out


def find(target_id, discover=False):
    for t in targets(discover=discover or target_id.startswith("ct:")):
        if t["target"] == target_id:
            return t
    return None


def remote(t, cmd, timeout=300, binary=False, root=False):
    """Run `cmd` on a target. Returns (rc, stdout, stderr).
    root=True on a plain linux host uses sudo -S with the host's `sudo_secret`."""
    kind = t["kind"]
    if kind == "node":
        return run(SSH + [t["ssh"], cmd], timeout=timeout, binary=binary)
    if kind == "ct":
        return run(SSH + [t["ssh"], f"pct exec {t['vmid']} -- sh -c {sh_quote(cmd)}"], timeout=timeout, binary=binary)
    if kind in ("host", "local", "images", "firmware"):
        if t.get("vmid"):          # docker inside an LXC
            return run(SSH + [t["ssh"], f"pct exec {t['vmid']} -- sh -c {sh_quote(cmd)}"],
                       timeout=timeout, binary=binary)
        inp = None
        if root and t.get("root_via") == "docker":
            # No sudo on the box (ZimaOS), but its user is in the docker group = root in all but name.
            # A throwaway container chrooted into the host's / runs the command as real root, nothing installed.
            img = config.get("estate.root_image") or "alpine:latest"
            cmd = (f"docker run --rm -i --privileged --pid=host --net=host -v /:/host {img} "
                   f"chroot /host sh -c {sh_quote(cmd)}")
        elif root and t.get("sudo_secret"):
            pw = secrets.get(t["sudo_secret"])
            if not pw:
                raise RuntimeError(f"{t['target']}: sudo password secret {t['sudo_secret']} is not set")
            cmd, inp = f"sudo -S -p '' sh -c {sh_quote(cmd)}", (pw + "\n") if not binary else (pw + "\n").encode()
        elif root and not t.get("ssh", "").startswith("root@") and kind != "local":
            cmd = f"sudo -n sh -c {sh_quote(cmd)}"
        if kind == "local" or t.get("local") or not t.get("ssh"):
            return run(["sh", "-c", cmd], timeout=timeout, binary=binary, inp=inp)
        return run(SSH + [t["ssh"], cmd], timeout=timeout, binary=binary, inp=inp)
    raise ValueError(kind)


def push(t, local_path, remote_path, mode="755"):
    """Copy one file onto a target (used to ship the verified trivy binary). Returns (ok, error)."""
    if t["kind"] == "local" or t.get("local") or not t.get("ssh"):
        shutil.copy(local_path, remote_path)
        return True, ""
    if t.get("vmid"):
        rc, _, se = run(["scp", "-q", "-o", "BatchMode=yes", local_path, f"{t['ssh']}:{remote_path}"], timeout=300)
        rc2, _, se2 = run(SSH + [t["ssh"], f"pct push {t['vmid']} {remote_path} {remote_path} --perms {mode} "
                                           f"&& rm -f {remote_path}"])
        return (rc == 0 and rc2 == 0), (se or se2 or "").strip()[:160]
    rc, _, se = run(["scp", "-q", "-o", "BatchMode=yes", local_path, f"{t['ssh']}:{remote_path}"], timeout=300)
    return rc == 0, (se or "").strip()[:160]


def docker_host(img_target_id):
    """The images-target (`img:<name>`) whose Docker daemon runs the `ctr:<name>:<container>` containers."""
    for t in targets(discover=False):
        if t["target"] == img_target_id:
            return t
    raise ValueError(f"unknown docker host {img_target_id}")


def check(t, timeout=15):
    """Can we reach it? (rc==0 of a trivial command). Used by the setup wizard and /health."""
    try:
        rc, so, se = remote(t, "echo ok", timeout=timeout)
        return rc == 0 and "ok" in (so or ""), (se or "").strip()[:160]
    except Exception as e:  # noqa: BLE001
        return False, str(e)[:160]
