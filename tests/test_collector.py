"""Ajan collector testleri: FIM (dosya bütünlüğü) + auth-log başarısız giriş tail."""
from aegis_agent.collector import TelemetryCollector


def test_fim_detects_created_modified_deleted(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("v1")
    col = TelemetryCollector(watch_paths=[str(tmp_path)])  # baseline: a.txt=v1

    f.write_text("v2-changed")
    modified = col.collect_file_changes()
    assert any(e["data"]["action"] == "modified" and e["data"]["path"].endswith("a.txt") for e in modified)

    (tmp_path / "b.txt").write_text("new")
    created = col.collect_file_changes()
    assert any(e["data"]["action"] == "created" for e in created)

    f.unlink()
    deleted = col.collect_file_changes()
    assert any(e["data"]["action"] == "deleted" for e in deleted)


def test_auth_failure_tail(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("startup line\n")
    col = TelemetryCollector(auth_log=str(log))  # offset = mevcut boyut

    with open(log, "a", encoding="utf-8") as f:
        f.write("Jun 21 10:00 host sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2\n")
        f.write("Jun 21 10:01 host sshd[1]: Failed password for invalid user admin from 198.51.100.2 port 22 ssh2\n")

    events = col.collect_auth_failures()
    assert len(events) == 2
    assert events[0]["data"] == {"username": "root", "source_ip": "203.0.113.9"}
    assert events[1]["data"]["username"] == "admin"
    # Yeni satır yoksa boş döner (offset ilerledi)
    assert col.collect_auth_failures() == []


def test_no_watch_no_events(tmp_path):
    col = TelemetryCollector()
    assert col.collect_file_changes() == []
    assert col.collect_auth_failures() == []
