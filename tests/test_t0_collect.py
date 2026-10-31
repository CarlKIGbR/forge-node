import json
import re
from pathlib import Path

from forge_node.t0 import collect, runner
from forge_node.t0.runner import Run

from n2_helpers import FakeRunner, NOW, make_env, policy_doc, view
from test_t0_parse import APT, FINDMNT, LSBLK

ROOT = Path(__file__).resolve().parents[1]


def test_host_section_reads_proc_and_timedatectl(tmp_path):
    r = FakeRunner({"timedatectl": "Timezone=Europe/Berlin\nNTPSynchronized=yes\nNTP=yes\nTimeUSec=Sat\n"})
    env = make_env(tmp_path, r, files={"/var/run/reboot-required": "*** System restart required ***\n"})
    h = collect.host(env)
    assert h["os"]["pretty_name"].startswith("Ubuntu") and h["kernel"]["release"] == "6.8.0-48-generic" and h["hostname"]["name"] == "carlgpu2"
    assert h["cpu"] == {"status": "ok", "threads": 2, "model": "AMD Ryzen 9 7950X"} and h["load"]["load1_milli"] == 520 and h["uptime"]["seconds"] == 123456
    m = h["memory"]
    assert m["swap_total"] == 2097148 * 1024 and m["swap_used"] == (2097148 - 1900000) * 1024 and h["time"]["ntp_synchronized"] is True and h["reboot_required"]["required"] is True


def test_host_degrades_per_section_not_per_op(tmp_path):
    env = make_env(tmp_path, FakeRunner({}), files={})
    (tmp_path / "proc/uptime").unlink()
    h = collect.host(env)
    assert h["uptime"]["status"] == "unavailable" and h["time"]["status"] == "unavailable" and h["cpu"]["status"] == "ok" and h["reboot_required"]["required"] is False


def test_disks_tags_protected_mounts_nfs_and_unresponsive_statvfs(tmp_path):
    r = FakeRunner({"lsblk": LSBLK, "findmnt": FINDMNT})
    env = make_env(tmp_path, r, files={"/proc/mdstat": "Personalities :\nunused devices: <none>\n"})
    calls = []

    def fake_statvfs(path, timeout=3.0):
        calls.append(path)
        return {"unresponsive": True} if path == "/srv/models" else {"size": 100, "avail": 40, "used": 60}
    d = collect.disks(env, statvfs=fake_statvfs)
    mounts = {m["target"]: m for m in d["mounts"]["mounts"]}
    assert set(mounts) == {"/", "/srv/models"} and "/proc" not in mounts                # pseudo filesystems are dropped
    assert mounts["/srv/models"]["protected"] is True and mounts["/srv/models"]["role"] == "kmu-protected" and mounts["/"]["protected"] is False
    assert mounts["/srv/models"]["df"] == {"unresponsive": True} and mounts["/"]["df"]["avail"] == 40
    assert [x["name"] for x in d["block_devices"]["devices"]][:1] == ["nvme0n1"] and d["nfs_mounts"]["mounts"][0]["target"] == "/mnt/nas"
    assert d["md_raid"]["arrays"] == [] and d["smart"]["status"] == "unavailable"
    assert d["nvme"]["status"] == "unavailable"                                          # no /sys/class/nvme in the fake tree


def test_disks_nvme_controllers_via_sys_symlinks(tmp_path):
    import os
    r = FakeRunner({"lsblk": LSBLK, "findmnt": FINDMNT})
    env = make_env(tmp_path, r, files={"/sys/devices/pci/nvme0/model": "Samsung 990\n", "/sys/devices/pci/nvme0/state": "live\n", "/sys/devices/pci/nvme0/transport": "pcie\n"})
    (tmp_path / "sys/class/nvme").mkdir(parents=True)
    os.symlink("../../devices/pci/nvme0", tmp_path / "sys/class/nvme/nvme0")
    d = collect.disks(env, statvfs=lambda p, timeout=3.0: None)
    assert d["nvme"]["controllers"] == [{"name": "nvme0", "model": "Samsung 990", "state": "live", "transport": "pcie"}]


def test_statvfs_helper_times_out_instead_of_hanging(monkeypatch):
    import os
    import time
    assert collect._statvfs("/proc")["size"] >= 0 and collect._statvfs("/nonexistent-path-for-test") is None
    def slow(p):
        time.sleep(2)
        raise OSError("late")
    monkeypatch.setattr(os, "statvfs", slow)
    t0 = time.monotonic()
    assert collect._statvfs("/mnt/dead-nfs", timeout=0.2) == {"unresponsive": True} and time.monotonic() - t0 < 1.5


def test_gpu_present_and_absent(tmp_path):
    csv = "0, GPU-aaaa, RTX 4090, 1024, 24564, 3, 41, 70.12, 450.00, 210, 2520, 4, 16, 0x0\n"
    env = make_env(tmp_path, FakeRunner({"nvidia_gpus": csv, "nvidia_apps": "GPU-aaaa, 77, /usr/bin/python3 --token=x, 512\n"}))
    g = collect.gpu(env)
    assert g["gpus"]["gpus"][0]["name"] == "RTX 4090" and "uuid" not in g["gpus"]["gpus"][0] and g["compute_apps"]["apps"] == [{"pid": 77, "process": "python3", "used_mib": 512, "gpu_index": 0}]
    g = collect.gpu(make_env(tmp_path, FakeRunner({})))
    assert g["gpus"] == {"status": "unavailable", "reason": "command not installed"}


def test_units_failed_list_and_timers(tmp_path):
    show = ("Id=a.service\nLoadState=loaded\nActiveState=active\nSubState=running\nResult=success\nFragmentPath=/etc/systemd/system/a.service\nDescription=A\nNRestarts=0\n\n"
            "Id=kmu-sicherung-system.service\nLoadState=loaded\nActiveState=failed\nSubState=failed\nResult=exit-code\nFragmentPath=/etc/systemd/system/kmu-sicherung-system.service\nDescription=Backup\nNRestarts=0\n\n"
            "Id=b.socket\nLoadState=loaded\nActiveState=inactive\nSubState=dead\nResult=success\nFragmentPath=\nDescription=B\nNRestarts=\n\n")
    timers = json.dumps([{"unit": "apt-daily.timer", "activates": "apt-daily.service", "next": 1730000000000000, "last": 1729990000000000}])
    u = collect.units(make_env(tmp_path, FakeRunner({"systemctl_show_all": show, "systemctl_list_timers": timers})))
    assert u["units"]["count"] == 3 and u["units"]["failed"] == ["kmu-sicherung-system.service"] and u["units"]["listed"][0]["unit"] == "kmu-sicherung-system.service"
    assert {x["unit"] for x in u["units"]["listed"]} == {"a.service", "kmu-sicherung-system.service"} and u["timers"]["timers"][0]["next_us"] == 1730000000000000
    assert u["units"]["listed"][1]["fragment"] == "/etc/systemd/system/a.service"


UU_LOG_OK = "2026-10-31 06:25:01,100 INFO Starting unattended upgrades script\n2026-10-31 06:25:01,200 INFO Allowed origins are: o=Ubuntu,a=noble, o=Ubuntu,a=noble-security\n2026-10-31 06:25:05,100 INFO All upgrades installed\n"
UU_CONF = ('APT::Periodic::Unattended-Upgrade "1";\nUnattended-Upgrade::Allowed-Origins:: "${distro_id}:${distro_codename}";\nUnattended-Upgrade::Allowed-Origins:: "${distro_id}:${distro_codename}-security";\n')
DPKG = "docker-ce\t5:29.2.1-1\tii \nunattended-upgrades\t2.9.1\tii \nnvidia-driver-570\t570.1\tii \n"


UNREADABLE = {"status": "unavailable", "reason": "no privileged probe in this test"}


def pkgs_env(tmp_path, conf=UU_CONF, log=UU_LOG_OK, **extra):
    r = FakeRunner({"apt_config_dump": conf, "dpkg_versions": DPKG, "apt_simulate": APT, "apt_showhold": "linux-image-generic\nnvidia-driver-570\n", **extra})
    files = {"/var/log/unattended-upgrades/unattended-upgrades.log": log} if log is not None else {}
    return make_env(tmp_path, r, files=files), r


def test_inv_pkgs_reports_unattended_upgrades_status_and_last_run(tmp_path):
    env, _ = pkgs_env(tmp_path)
    p = collect.pkgs(env, UNREADABLE)
    uu = p["unattended_upgrades"]
    assert uu["installed"] and uu["enabled"] and uu["last_run"] == "2026-10-31 06:25:01" and uu["last_result"] == "installed" and not uu["drift"] and not uu["failed_last_run"]
    assert p["pending"]["total"] == 3 and p["pending"]["security"] == 1 and p["pending"]["security_packages"] == ["libssl3t64"]
    assert p["holds"]["packages"] == ["linux-image-generic", "nvidia-driver-570"] and p["versions"]["packages"][0]["package"] == "docker-ce" and p["versions"]["kernel"] == "6.8.0-48-generic"


def test_inv_pkgs_flags_origin_drift_and_failed_run(tmp_path):
    conf = UU_CONF + 'Unattended-Upgrade::Allowed-Origins:: "${distro_id}:${distro_codename}-updates";\nUnattended-Upgrade::Automatic-Reboot "true";\n'
    log = "2026-10-31 06:25:01,100 INFO Starting unattended upgrades script\n2026-10-31 06:25:01,200 INFO Allowed origins are: o=Ubuntu,a=noble-proposed\n2026-10-31 06:25:09,100 ERROR Installing the upgrades failed!\n"
    env, _ = pkgs_env(tmp_path, conf=conf, log=log)
    uu = collect.pkgs(env, UNREADABLE)["unattended_upgrades"]
    assert uu["drift"] is True and "${distro_id}:${distro_codename}-updates" in uu["origin_drift"] and "o=Ubuntu,a=noble-proposed" in uu["origin_drift"]
    assert uu["failed_last_run"] is True and uu["last_result"] == "failed" and uu["automatic_reboot"] is True


def test_inv_pkgs_without_log_or_with_uu_disabled(tmp_path):
    env, _ = pkgs_env(tmp_path, conf='APT::Periodic::Unattended-Upgrade "0";\n', log=None)
    uu = collect.pkgs(env, UNREADABLE)["unattended_upgrades"]
    assert uu["enabled"] is False and uu["last_result"] == "log_unreadable"


def test_forge_node_never_modifies_apt_config(tmp_path):
    env, r = pkgs_env(tmp_path)
    collect.pkgs(env, UNREADABLE)
    assert {c for c, _ in r.calls} <= {"apt_config_dump", "dpkg_versions", "apt_simulate", "apt_showhold"}
    for cid in ("apt_simulate", "apt_showhold", "apt_config_dump"):
        argv = runner.CMDS[cid].argv
        assert argv[0] in ("-s", "showhold", "dump") and not any(a in ("install", "upgrade-apply", "dist-upgrade", "remove", "purge", "update", "-y") for a in argv)
    assert "Debug::NoLocking=1" in runner.CMDS["apt_simulate"].argv
    src = "\n".join(p.read_text() for p in (ROOT / "src").rglob("*.py"))
    assert not re.search(r"(?:open|write_text|write_bytes|unlink|rename|replace)\([^)]*/etc/apt", src)
    from forge_node import gates
    assert not any(re.search(r"apt|upgrade", op) for op in gates.OPS)


def test_backups_units_from_policy_patterns_and_paths_ages(tmp_path):
    pol = view(policy_doc(t0={"backup_units": ["kmu-sicherung-*", "kmu-s2-backup.*"], "backup_dirs": ["/srv/backup/restic-marker", "/srv/backup/dumps"]}))
    lu = json.dumps([{"unit": "kmu-sicherung-system.service"}, {"unit": "kmu-sicherung-system.timer"}, {"unit": "other.service"}, {"unit": "kmu-s2-backup.timer"}])
    show = "Id=kmu-sicherung-system.service\nActiveState=inactive\nSubState=dead\nResult=success\nExecMainStatus=0\nExecMainExitTimestamp=Sat 2026-10-31 03:21:00 CET\n"
    timers = json.dumps([{"unit": "kmu-sicherung-system.timer", "activates": "kmu-sicherung-system.service", "next": 5, "last": 4}, {"unit": "apt-daily.timer", "activates": "apt-daily.service", "next": 1, "last": 1}])
    r = FakeRunner({"systemctl_list_units": lu, "systemctl_show_unit": show, "systemctl_list_timers": timers})
    env = make_env(tmp_path, r, policy=pol, files={"/srv/backup/restic-marker": "snapshot 612f13f0\n", "/srv/backup/dumps/a.sql": "x"})
    import os
    os.utime(tmp_path / "srv/backup/restic-marker", (NOW.timestamp() - 7200, NOW.timestamp() - 7200))
    os.utime(tmp_path / "srv/backup/dumps/a.sql", (NOW.timestamp() - 90000, NOW.timestamp() - 90000))
    b = collect.backups(env)
    assert [c for c in r.calls if c[0] == "systemctl_show_unit"][0][1]["unit"] == ["kmu-s2-backup.timer", "kmu-sicherung-system.service", "kmu-sicherung-system.timer"]
    assert b["units"]["units"][0]["result"] == "success" and [t["unit"] for t in b["timers"]["timers"]] == ["kmu-sicherung-system.timer"]
    paths = {p["path"]: p for p in b["paths"]["paths"]}
    assert paths["/srv/backup/restic-marker"]["age_s"] == 7200 and paths["/srv/backup/dumps"]["newest_age_s"] == 90000 and paths["/srv/backup/dumps"]["entries"] == 1


def test_backups_missing_path_reports_error_not_exception(tmp_path):
    pol = view(policy_doc(t0={"backup_units": [], "backup_dirs": ["/srv/backup/none"]}))
    b = collect.backups(make_env(tmp_path, FakeRunner({"systemctl_list_units": "[]"}), policy=pol))
    assert b["paths"]["paths"][0]["error"] in ("unreadable", "escape") and b["units"]["units"] == []


def test_net_local_routes_and_ufw(tmp_path):
    r = FakeRunner({"ip_route": json.dumps([{"dst": "default", "gateway": "192.168.10.1", "dev": "eno1"}]), "ss_listen": "tcp LISTEN 0 4096 127.0.0.1:5432 0.0.0.0:*\n"})
    env = make_env(tmp_path, r, files={"/etc/ufw/ufw.conf": "# x\nENABLED=no\nLOGLEVEL=low\n"})
    n = collect.net_local(env)
    assert n["routes"]["default_gateways"] == ["192.168.10.1"] and n["ufw"]["enabled"] is False
    assert collect.listeners_unprivileged(env)["processes_visible"] is False


def test_own_certs_days_left(tmp_path):
    out = "notAfter=Nov 14 12:00:00 2026 GMT\nsubject=CN=forge-node-g2\nsha256 Fingerprint=" + ":".join(["AB"] * 32) + "\n"
    env = make_env(tmp_path, FakeRunner({"openssl_x509_file": out}))
    c = collect.own_certs(env, "/etc/forge-node/pki/node.crt", NOW)
    assert c["days_left"] == 13 and c["status"] == "ok" and "not_after_epoch" not in c
    assert collect.own_certs(env, None, NOW)["status"] == "unavailable"
    assert collect.own_certs(make_env(tmp_path, FakeRunner({})), "/x", NOW)["status"] == "unavailable"


def test_local_tls_reports_not_listening(tmp_path):
    t = collect.local_tls(make_env(tmp_path, FakeRunner({})))
    assert [r["port"] for r in t["listeners"]] == [443, 8443] and all(r.get("listening") is False for r in t["listeners"])


def test_inv_pkgs_prefers_the_root_probe_answer_because_the_log_directory_is_root_adm_0750(tmp_path):
    """Live proof: /var/log/unattended-upgrades is root:adm 0750, the agent uid cannot read it."""
    env, _ = pkgs_env(tmp_path, log=None)
    root = {"status": "ok", "last_run": "2026-10-31 06:25:01", "result": "failed", "origins": ["o=Ubuntu,a=noble-updates", ""]}
    uu = collect.pkgs(env, root)["unattended_upgrades"]
    assert uu["last_run"] == "2026-10-31 06:25:01" and uu["failed_last_run"] is True and uu["drift"] is True and uu["origin_drift"] == ["o=Ubuntu,a=noble-updates"]
    assert collect.pkgs(env, UNREADABLE)["unattended_upgrades"]["last_result"] == "log_unreadable"
    assert collect.pkgs(env, {"status": "ok"})["unattended_upgrades"]["last_result"] == "unknown"


def test_empty_apt_config_values_are_not_origins(tmp_path):
    conf = 'APT::Periodic::Unattended-Upgrade "1";\nUnattended-Upgrade::Allowed-Origins "";\nUnattended-Upgrade::Allowed-Origins:: "${distro_id}:${distro_codename}-security";\n'
    env, _ = pkgs_env(tmp_path, conf=conf)
    uu = collect.pkgs(env, UNREADABLE)["unattended_upgrades"]
    assert uu["origins_configured"] == ["${distro_id}:${distro_codename}-security"] and uu["drift"] is False


def test_der_cert_reports_hub_certificate_expiry(tmp_path):
    out = "notAfter=Nov 14 12:00:00 2026 GMT\nsubject=CN=forge-nodehub\nsha256 Fingerprint=" + ":".join(["AB"] * 32) + "\n"
    seen = {}
    r = FakeRunner({"openssl_x509_der": lambda slots, stdin: (seen.setdefault("der", stdin), Run(True, "ok", 0, out.encode()))[1]})
    env = make_env(tmp_path, r)
    c = collect.der_cert(env, b"\x30\x82")
    assert c["status"] == "ok" and c["days_left"] == 13 and c["subject"] == "CN=forge-nodehub" and seen["der"] == b"\x30\x82"
    assert collect.der_cert(env, None)["status"] == "unavailable"
    assert collect.der_cert(make_env(tmp_path, FakeRunner({})), b"x")["status"] == "unavailable"
