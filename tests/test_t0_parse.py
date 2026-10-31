import json

from forge_node.t0 import parse

LSBLK = json.dumps({"blockdevices": [
    {"name": "nvme0n1", "kname": "nvme0n1", "type": "disk", "size": 1000204886016, "fstype": None, "mountpoints": [None], "ro": False, "rota": False, "model": "Samsung SSD 990 PRO 1TB      ", "pkname": None,
     "children": [{"name": "nvme0n1p2", "type": "part", "size": 999000000000, "fstype": "ext4", "mountpoints": ["/"], "ro": False, "rota": False, "model": None, "pkname": "nvme0n1"}]},
    {"name": "nvme1n1", "type": "disk", "size": 2000398934016, "fstype": "ext4", "mountpoints": ["/srv/models"], "ro": False, "rota": False, "model": "WD_BLACK", "pkname": None}]})
FINDMNT = json.dumps({"filesystems": [{"target": "/", "source": "/dev/nvme0n1p2", "fstype": "ext4", "options": "rw,relatime",
                                       "children": [{"target": "/srv/models", "source": "/dev/nvme1n1", "fstype": "ext4", "options": "rw"}, {"target": "/proc", "source": "proc", "fstype": "proc", "options": "rw"}]}]})
SS = ('tcp   LISTEN 0      4096       127.0.0.1:5432       0.0.0.0:*    users:(("postgres",pid=812,fd=6))\n'
      'tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*    users:(("sshd",pid=900,fd=3),("sshd",pid=901,fd=3))\n'
      'tcp   LISTEN 0      4096            [::]:11434         [::]:*\n'
      'udp   UNCONN 0      0                  *:5353              *:*\n'
      'garbage line\n')


def test_numbers_have_no_floats():
    assert parse.milli("70.12") == 70120 and parse.milli("[N/A]") is None and parse.milli("") is None
    assert parse.to_int(" 12 ") == 12 and parse.to_int("x") is None


def test_proc_parsers():
    assert parse.meminfo("MemTotal:  100 kB\nSwapFree: 5 kB\nbad\n") == {"MemTotal": 102400, "SwapFree": 5120}
    assert parse.cpuinfo("processor : 0\nmodel name : X\nprocessor : 1\nmodel name : X\n") == {"threads": 2, "model": "X"}
    assert parse.loadavg("0.52 0.40 0.30 1/5 1\n") == {"load1_milli": 520, "load5_milli": 400, "load15_milli": 300} and parse.loadavg("") == {}
    assert parse.uptime("123.9 5\n") == 123 and parse.uptime("") is None
    assert parse.os_release('PRETTY_NAME="Ubuntu 24.04 LTS"\nVERSION_ID="24.04"\nOTHER=x\n') == {"pretty_name": "Ubuntu 24.04 LTS", "version_id": "24.04"}
    assert parse.cgroup_v2_path("0::/system.slice/docker-abc.scope\n") == "/system.slice/docker-abc.scope" and parse.cgroup_v2_path("1:cpu:/x\n") is None
    assert parse.kv_file("usage_usec 123\nuser_usec 5\nname x\n") == {"usage_usec": 123, "user_usec": 5}
    assert parse.io_stat("259:0 rbytes=100 wbytes=50 rios=1\n259:1 rbytes=1 wbytes=2\n") == {"rbytes": 101, "wbytes": 52}


def test_mdstat_and_mounts_and_diskstats_net():
    md = "Personalities : [raid1]\nmd0 : active raid1 sdb1[1] sda1[0]\n      1000 blocks [2/2] [UU]\n\nunused devices: <none>\n"
    assert parse.mdstat(md) == [{"name": "md0", "state": "active", "level": "raid1", "devices": ["sdb1", "sda1"], "health": "UU"}]
    assert parse.mounts("10.0.0.3:/exp\\040x /mnt/a\\040b nfs4 rw 0 0\n")[0]["target"] == "/mnt/a b"
    ds = parse.diskstats("259 0 nvme0n1 100 0 2000 50 200 0 4000 80 3 130 0 0\n259 1 nvme0n1p1 1 0 1 1 1 0 1 1 0 1 0 0\n7 0 loop0 1 0 1 0 0 0 0 0 0 0 0 0\n8 0 sda 1 0 1 0 1 0 1 0 0 0 0 0\n8 1 sda1 1 0 1 0 1 0 1 0 0 0 0 0\n")
    assert set(ds) == {"nvme0n1", "sda"} and ds["nvme0n1"] == {"rd_sectors": 2000, "wr_sectors": 4000, "io_ms": 130, "inflight": 3, "rd_ios": 100, "wr_ios": 200}
    assert parse.net_dev("h\nh\n    lo: 1 1 0 0 0 0 0 0 1 1\n  eth0: 5 1 0 0 0 0 0 0 7 1\n") == {"eth0": {"rx_bytes": 5, "tx_bytes": 7}}
    assert parse.cpu_times("cpu  1000 0 500 8000 100 0 0 0\ncpu0 1\n") == {"total": 9600, "idle": 8100}


def test_lsblk_findmnt():
    devs = parse.lsblk(LSBLK)
    assert [d["name"] for d in devs] == ["nvme0n1", "nvme0n1p2", "nvme1n1"] and devs[0]["model"] == "Samsung SSD 990 PRO 1TB" and devs[1]["parent"] == "nvme0n1" and devs[2]["mountpoints"] == ["/srv/models"]
    assert parse.lsblk("not json") == [] and parse.findmnt("x") == []
    assert [m["target"] for m in parse.findmnt(FINDMNT)] == ["/", "/srv/models", "/proc"]


def test_kv_blocks_and_timedatectl():
    t = "Id=a.service\nActiveState=active\nDescription=A = B\n\nId=b.service\nActiveState=failed\n\n\n"
    b = parse.kv_blocks(t)
    assert len(b) == 2 and b[0]["Description"] == "A = B" and b[1]["ActiveState"] == "failed"
    assert parse.timedatectl("Timezone=Europe/Berlin\nNTPSynchronized=yes\nNTP=yes\n") == {"timezone": "Europe/Berlin", "ntp_synchronized": True, "ntp_enabled": True}


def test_nvidia_gpus_and_apps():
    csv = "0, GPU-aaaa, NVIDIA GeForce RTX 4090, 1024, 24564, 3, 41, 70.12, 450.00, 210, 2520, 4, 16, 0x0000000000000004\n1, GPU-bbbb, NVIDIA A4000, [N/A], 16376, 0, 35, [N/A], 140.00, 300, 1560, 4, 16, 0x0\n"
    g = parse.nvidia_gpus(csv)
    assert g[0]["power_mw"] == 70120 and g[0]["throttle"] == ["sw_power_cap"] and g[0]["mem_total_mib"] == 24564 and g[1]["mem_used_mib"] is None and g[1]["power_mw"] is None
    apps = parse.nvidia_apps("GPU-aaaa, 1234, /usr/bin/python3 -c secret=abc, 512\nGPU-bbbb, 99, /opt/ollama/bin/ollama, 9000\nshort, row\n")
    assert apps[1] == {"gpu_uuid": "GPU-bbbb", "pid": 99, "process": "ollama", "used_mib": 9000} and len(apps) == 2


def test_ss_listeners():
    r = parse.ss(SS)
    assert r[0] == {"proto": "tcp", "addr": "127.0.0.1", "port": 5432, "state": "LISTEN", "processes": ["postgres"]}
    assert r[1]["processes"] == ["sshd"] and r[2]["addr"] == "::" and r[2]["port"] == 11434 and r[2]["processes"] == [] and r[3]["proto"] == "udp" and len(r) == 4


def test_ip_routes():
    r = parse.ip_routes(json.dumps([{"dst": "default", "gateway": "192.168.10.1", "dev": "eno1"}, {"dst": "192.168.10.0/29", "dev": "eno1", "prefsrc": "192.168.10.4"}]))
    assert r["default_gateways"] == ["192.168.10.1"] and len(r["routes"]) == 2 and parse.ip_routes("x") == {"routes": [], "default_gateways": []}


APT = ("Inst libssl3t64 [3.0.13-0ubuntu3.4] (3.0.13-0ubuntu3.5 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])\n"
       "Inst vim [2:9.1.0016-1ubuntu7.3] (2:9.1.0016-1ubuntu7.4 Ubuntu:24.04/noble-updates [amd64])\n"
       "Inst newpkg (1.0 Ubuntu:24.04/noble [all])\nConf libssl3t64 (3.0.13 Ubuntu [amd64])\n")


def test_apt_simulate_flags_security():
    r = parse.apt_simulate(APT)
    assert [(p["package"], p["security"]) for p in r] == [("libssl3t64", True), ("vim", False), ("newpkg", False)] and r[2]["old"] is None


def test_apt_config_and_origin_classes():
    dump = ('APT::Periodic::Unattended-Upgrade "1";\nUnattended-Upgrade::Allowed-Origins "";\nUnattended-Upgrade::Allowed-Origins:: "${distro_id}:${distro_codename}";\n'
            'Unattended-Upgrade::Allowed-Origins:: "${distro_id}:${distro_codename}-security";\nUnattended-Upgrade::Allowed-Origins:: "${distro_id}:${distro_codename}-updates";\n'
            'Unattended-Upgrade::Package-Blacklist:: "linux-image-*";\nDir "/";\n')
    c = parse.apt_config(dump)
    assert c["APT::Periodic::Unattended-Upgrade"] == ["1"] and len(c["Unattended-Upgrade::Allowed-Origins"]) == 4 and c["Unattended-Upgrade::Package-Blacklist"] == ["linux-image-*"]
    assert [parse.origin_class(x) for x in c["Unattended-Upgrade::Allowed-Origins"][1:]] == ["base", "security", "other"]
    assert parse.origin_class("${distro_id}ESM:${distro_codename}-infra-security") == "security" and parse.origin_class("o=Ubuntu,a=noble-proposed") == "other" and parse.origin_class("origin=Ubuntu,archive=noble") == "base"


def test_uu_log_last_run_and_result():
    log = ("2026-10-30 06:25:01,100 INFO Starting unattended upgrades script\n2026-10-30 06:25:01,200 INFO Allowed origins are: o=Ubuntu,a=noble, o=Ubuntu,a=noble-security\n"
           "2026-10-30 06:25:05,100 INFO All upgrades installed\n2026-10-31 06:25:01,100 INFO Starting unattended upgrades script\n2026-10-31 06:25:01,200 INFO Allowed origins are: o=Ubuntu,a=noble-updates\n"
           "2026-10-31 06:25:09,100 ERROR Installing the upgrades failed!\n")
    r = parse.uu_log(log)
    assert r["last_run"] == "2026-10-31 06:25:01" and r["result"] == "failed" and r["origins"] == ["o=Ubuntu,a=noble-updates"]
    assert parse.uu_log("2026-10-31 06:25:01,1 INFO Starting unattended upgrades script\n2026-10-31 06:25:01,2 INFO Allowed origins are: o=Ubuntu,a=noble, o=Ubuntu,a=noble-security\n")["origins"] == ["o=Ubuntu,a=noble", "o=Ubuntu,a=noble-security"]
    assert parse.uu_log("2026-10-31 06:25:01,100 INFO Starting unattended upgrades script\n2026-10-31 06:25:02,000 INFO No packages found that can be upgraded unattended and no pending auto-removals\n")["result"] == "nothing_to_do"
    assert parse.uu_log("")["result"] == "no_run_recorded"


def test_x509_and_misc():
    out = "notAfter=Nov 14 12:00:00 2026 GMT\nsubject=CN=forge-node-g2\nsha256 Fingerprint=" + ":".join(["AB"] * 32) + "\n"
    r = parse.x509(out)
    assert r["not_after"] == "2026-11-14T12:00:00Z" and r["subject"] == "CN=forge-node-g2" and r["sha256"] == "ab" * 32 and r["not_after_epoch"] > 0
    assert parse.x509("garbage")["not_after"] is None
    assert parse.dpkg_versions("docker-ce\t5:29.2.1\tii \nfoo\t1\trc \nbad\n") == [{"package": "docker-ce", "version": "5:29.2.1"}]
    assert parse.du_bytes("12345\t/srv/models/x\n") == 12345 and parse.du_bytes("du: oops") is None
    assert parse.virsh_table(" Id   Name    State\n------------------\n 1    vm1     running\n -    vm2     shut off\n") == [{"id": "1", "name": "vm1", "state": "running"}, {"id": "-", "name": "vm2", "state": "shut off"}]
    assert parse.sshd_effective("port 22\nallowusers carl\nallowusers tbpost@10.200.0.2\nhostkey /etc/ssh/ssh_host_ed25519_key\n") == {"port": ["22"], "allowusers": ["carl", "tbpost@10.200.0.2"]}
    assert parse.etc_group("docker:x:984:carl,forge\nsudo:x:27:\n", ("docker", "sudo", "adm")) == {"docker": ["carl", "forge"], "sudo": [], "adm": []}


def test_authorized_keys_gives_fingerprints_and_comments_never_bodies_or_options():
    body = "AAAAC3NzaC1lZDI1NTE5AAAAIOCnQJdkGAnqC9RpKFPyX3e4R8Y5v0QG9hJmFqQqkG8E"
    text = f'# comment\ncommand="/usr/bin/secret --token=abc",no-pty ssh-ed25519 {body} carl@mac\nssh-ed25519 {body}\nssh-rsa !!!notbase64 x\nnonsense\n'
    r = parse.authorized_keys(text)
    assert len(r) == 2 and r[0]["fingerprint"].startswith("SHA256:") and r[0]["comment"] == "carl@mac" and r[0]["has_options"] and r[0]["fingerprint"] == r[1]["fingerprint"]
    assert body not in repr(r) and "token" not in repr(r) and "command" not in repr(r)
