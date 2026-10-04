"""统一参与方判定与写事务内复核（本轮权限边界）。

覆盖：
- 封存人交接确认提交后：旧封存人立即失去资料/审计/异议/快照签发与一切
  封存人写操作权限（统一 403，不区分资料是否存在），新封存人立即按现有
  规则获得权限；
- 见证人替换提交后：旧见证人立即失去资料/审计/异议/快照签发与同意权限，
  新见证人立即获得；
- 账号停用提交后：当前密钥的一切访问沿用既有 401（先于任何 403 判定），
  失效密钥不得借读写触发到期结算或留下业务审计；
- 写事务内复核：交接确认若在业务写等待写锁期间提交，旧封存人的开封申请/
  撤销/替换/清除安排/取消一律 403 并整体回滚（不写数据、不留业务审计）；
- 并发身份变更与操作按 BEGIN IMMEDIATE 提交顺序裁定（真实 uvicorn +
  多线程：交接确认 vs 旧封存人提交开封请求，只产生一个已提交终态）；
- 资料/异议编号不存在与无权沿用同一 403 文案；
- 历史通知仍仅供原收件人在凭据有效时读取/标记，不因失去资料权限而回收；
- 无账号的一次性阅览凭证兑换与可信公钥验真保持原有入口。
"""
import datetime as dt
import os
import socket
import sqlite3
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.conftest import auth, digest_of, register, seal  # noqa: E402


def _iso(hours: float = 1.0) -> str:
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=hours)).isoformat()


@pytest.fixture
def quiet_client(isolated_db, monkeypatch):
    """与 client 相同，但拉长后台扫描间隔，避免扫描器干扰锁内复核模拟。"""
    monkeypatch.setenv("SWEEP_INTERVAL_SECONDS", "3600")
    from app.main import app

    with TestClient(app) as c:
        yield c


def _handover(client, owner_key, new_key, doc_id):
    """完成一次交接：邀请 + 受让人确认。"""
    inv = client.post(
        f"/documents/{doc_id}/handover-invitations",
        json={"to_username": "new", "confirm_deadline": _iso(1)},
        headers=auth(owner_key),
    )
    assert inv.status_code == 201, inv.text
    inv_id = inv.json()["invitation_id"]
    cf = client.post(f"/handover-invitations/{inv_id}/confirm", headers=auth(new_key))
    assert cf.status_code == 200, cf.text
    return inv_id


def _audit_actions(client, key, doc_id):
    r = client.get(f"/documents/{doc_id}/audit", headers=auth(key))
    assert r.status_code == 200, r.text
    return [rec["action"] for rec in r.json()["records"]]


# ---------------------------------------------------------------------------
# 交接提交后：旧身份立即失权、新身份立即得权
# ---------------------------------------------------------------------------


def test_handover_commit_revokes_old_owner_access_everywhere(client):
    owner = register(client, "owner")
    new = register(client, "new")
    for n in ("w1", "w2", "w3"):
        register(client, n)
    doc_id = seal(client, owner, "统一权限正文 UNIFIED-SECRET", ["w1", "w2", "w3"])["document_id"]

    _handover(client, owner, new, doc_id)

    # 旧封存人：资料、审计、快照签发、全部封存人写操作 -> 统一 403
    assert client.get(f"/documents/{doc_id}", headers=auth(owner)).status_code == 403
    assert client.get(f"/documents/{doc_id}/audit", headers=auth(owner)).status_code == 403
    assert client.post(
        f"/documents/{doc_id}/audit-snapshots", headers=auth(owner)
    ).status_code == 403
    assert client.post(
        f"/documents/{doc_id}/open-requests",
        json={"reason": "旧身份申请", "deadline": _iso(2)},
        headers=auth(owner),
    ).status_code == 403
    assert client.post(
        f"/documents/{doc_id}/witness-replacements",
        json={"old_witness": "w3", "new_witness": "new"},
        headers=auth(owner),
    ).status_code == 403
    assert client.put(
        f"/documents/{doc_id}/purge", json={"purge_at": _iso(3)}, headers=auth(owner)
    ).status_code == 403
    assert client.delete(f"/documents/{doc_id}/purge", headers=auth(owner)).status_code == 403
    assert client.post(
        f"/documents/{doc_id}/handover-invitations",
        json={"to_username": "w1", "confirm_deadline": _iso(1)},
        headers=auth(owner),
    ).status_code == 403
    assert client.post(
        f"/documents/{doc_id}/view-passes", json={"expires_at": _iso(2)}, headers=auth(owner)
    ).status_code == 403

    # 新封存人：立即按现有规则获得权限
    got = client.get(f"/documents/{doc_id}", headers=auth(new))
    assert got.status_code == 200 and got.json()["status"] == "sealed"
    assert "body" not in got.json()
    assert client.get(f"/documents/{doc_id}/audit", headers=auth(new)).status_code == 200
    req = client.post(
        f"/documents/{doc_id}/open-requests",
        json={"reason": "新封存人申请", "deadline": _iso(2)},
        headers=auth(new),
    )
    assert req.status_code == 201, req.text
    assert client.put(
        f"/documents/{doc_id}/purge", json={"purge_at": _iso(3)}, headers=auth(new)
    ).status_code == 200
    assert client.delete(f"/documents/{doc_id}/purge", headers=auth(new)).status_code == 200
    assert client.post(
        f"/documents/{doc_id}/audit-snapshots", headers=auth(new)
    ).status_code == 201


def test_handover_commit_revokes_old_owner_objection_and_revoke_access(client):
    """交接后：旧封存人不能再查异议、不能撤销（自己此前提交的）开封请求。"""
    owner = register(client, "owner")
    new = register(client, "new")
    w = {n: register(client, n) for n in ("w1", "w2", "w3")}
    body = "异议联动正文 OBJ-HANDOVER-SECRET"
    dg = digest_of(body)
    doc_id = seal(client, owner, body, ["w1", "w2", "w3"])["document_id"]

    # 旧封存人的进行中开封请求 + w1 的未决异议
    req_id = client.post(
        f"/documents/{doc_id}/open-requests",
        json={"reason": "交接前申请", "deadline": _iso(2)},
        headers=auth(owner),
    ).json()["request_id"]
    obj_id = client.post(
        f"/documents/{doc_id}/objections",
        json={"observed_digest": dg, "reason": "摘要存疑"},
        headers=auth(w["w1"]),
    ).json()["objection_id"]

    _handover(client, owner, new, doc_id)

    # 旧封存人：异议查询与旧请求撤销 -> 403（异议/资料仍存在，只是无权）
    assert client.get(f"/objections/{obj_id}", headers=auth(owner)).status_code == 403
    assert client.post(
        f"/open-requests/{req_id}/revoke", json={}, headers=auth(owner)
    ).status_code == 403
    # 新封存人与当前见证人可见异议；新封存人同样被未决异议拦截
    assert client.get(f"/objections/{obj_id}", headers=auth(new)).status_code == 200
    assert client.get(f"/objections/{obj_id}", headers=auth(w["w2"])).status_code == 200
    assert client.post(
        f"/documents/{doc_id}/open-requests",
        json={"reason": "被异议拦截", "deadline": _iso(2)},
        headers=auth(new),
    ).status_code == 409


def test_witness_replacement_commit_revokes_old_witness_access(client):
    owner = register(client, "owner")
    w1, w2, w3 = (register(client, n) for n in ("w1", "w2", "w3"))
    w4 = register(client, "w4")
    body = "替换联动正文 REPLACE-UNIFIED-SECRET"
    dg = digest_of(body)
    doc_id = seal(client, owner, body, ["w1", "w2", "w3"])["document_id"]
    req_id = client.post(
        f"/documents/{doc_id}/open-requests",
        json={"reason": "替换前申请", "deadline": _iso(2)},
        headers=auth(owner),
    ).json()["request_id"]

    r = client.post(
        f"/documents/{doc_id}/witness-replacements",
        json={"old_witness": "w3", "new_witness": "w4"},
        headers=auth(owner),
    )
    assert r.status_code == 200 and r.json()["witnesses"] == ["w1", "w2", "w4"]

    # 旧见证人：资料/审计/快照签发/同意/异议 -> 403
    assert client.get(f"/documents/{doc_id}", headers=auth(w3)).status_code == 403
    assert client.get(f"/documents/{doc_id}/audit", headers=auth(w3)).status_code == 403
    assert client.post(
        f"/documents/{doc_id}/audit-snapshots", headers=auth(w3)
    ).status_code == 403
    assert client.post(
        f"/open-requests/{req_id}/approve", json={"digest": dg}, headers=auth(w3)
    ).status_code == 403
    assert client.post(
        f"/documents/{doc_id}/objections",
        json={"observed_digest": dg, "reason": "旧见证人异议"},
        headers=auth(w3),
    ).status_code == 403

    # 新见证人：立即按现有规则获得权限（查询、补票同意、签发快照）
    assert client.get(f"/documents/{doc_id}", headers=auth(w4)).status_code == 200
    ok = client.post(
        f"/open-requests/{req_id}/approve", json={"digest": dg}, headers=auth(w4)
    )
    assert ok.status_code == 200 and ok.json()["approval_count"] == 1
    assert client.post(
        f"/documents/{doc_id}/audit-snapshots", headers=auth(w4)
    ).status_code == 201


def test_deactivated_account_key_gets_401_everywhere(client):
    """账号停用提交后：旧密钥访问资料/审计/异议/快照/通知一律既有 401。"""
    owner = register(client, "owner")
    gone = register(client, "gone")
    w2, w3 = register(client, "w2"), register(client, "w3")
    body = "停用联动正文 DEACT-UNIFIED-SECRET"
    dg = digest_of(body)
    doc_id = seal(client, owner, body, ["gone", "w2", "w3"])["document_id"]
    # gone 作为见证人的资料开封后，其见证义务结清，可停用
    req_id = client.post(
        f"/documents/{doc_id}/open-requests",
        json={"reason": "开封", "deadline": _iso(2)},
        headers=auth(owner),
    ).json()["request_id"]
    client.post(f"/open-requests/{req_id}/approve", json={"digest": dg}, headers=auth(w2))
    client.post(f"/open-requests/{req_id}/approve", json={"digest": dg}, headers=auth(w3))
    assert client.get(f"/documents/{doc_id}", headers=auth(gone)).json()["status"] == "opened"

    r = client.post("/me/deactivation", headers=auth(gone))
    assert r.status_code == 200 and r.json()["status"] == "deactivated"

    bogus = {"detail": "凭据无效"}
    for resp in (
        client.get(f"/documents/{doc_id}", headers=auth(gone)),
        client.get(f"/documents/{doc_id}/audit", headers=auth(gone)),
        client.get("/objections/1", headers=auth(gone)),
        client.post(f"/documents/{doc_id}/audit-snapshots", headers=auth(gone)),
        client.get("/notifications", headers=auth(gone)),
        client.post("/notifications/1/read", headers=auth(gone)),
    ):
        assert resp.status_code == 401 and resp.json() == bogus
    # 与随机假密钥完全同文案（不区分账号是否存在/是否停用）
    assert client.get(f"/documents/{doc_id}", headers=auth("0" * 64)).json() == bogus


def test_rotated_key_gets_401_before_any_role_check(client):
    """失效密钥仍先返回既有 401：轮换后的旧密钥命中 401 而非 403。"""
    owner = register(client, "owner")
    for n in ("w1", "w2", "w3"):
        register(client, n)
    doc_id = seal(client, owner, "轮换优先正文 ROTATE-FIRST-SECRET", ["w1", "w2", "w3"])["document_id"]

    new_key = client.post("/me/api-key/rotate", headers=auth(owner)).json()["api_key"]
    # 旧密钥：一律 401（先于参与方/角色判定），新密钥照常
    assert client.put(
        f"/documents/{doc_id}/purge", json={"purge_at": _iso(3)}, headers=auth(owner)
    ).status_code == 401
    assert client.post(
        f"/documents/{doc_id}/open-requests",
        json={"reason": "旧密钥", "deadline": _iso(2)},
        headers=auth(owner),
    ).status_code == 401
    assert client.get(f"/documents/{doc_id}", headers=auth(owner)).status_code == 401
    assert client.get(f"/documents/{doc_id}", headers=auth(new_key)).status_code == 200


# ---------------------------------------------------------------------------
# 编号不存在与无权沿用同一拒绝结果
# ---------------------------------------------------------------------------


def test_missing_document_and_objection_ids_match_no_permission(client):
    owner = register(client, "owner")
    outsider = register(client, "outsider")
    w = {n: register(client, n) for n in ("w1", "w2", "w3")}
    body = "不可区分正文 INDISTINGUISHABLE-SECRET"
    dg = digest_of(body)
    doc_id = seal(client, owner, body, ["w1", "w2", "w3"])["document_id"]
    obj_id = client.post(
        f"/documents/{doc_id}/objections",
        json={"observed_digest": dg, "reason": "存疑"},
        headers=auth(w["w1"]),
    ).json()["objection_id"]

    # 资料：不存在编号与无权访问同一 403 同文案
    missing_doc = client.get("/documents/99999", headers=auth(outsider))
    forbidden_doc = client.get(f"/documents/{doc_id}", headers=auth(outsider))
    assert missing_doc.status_code == forbidden_doc.status_code == 403
    assert missing_doc.json() == forbidden_doc.json()

    # 异议：不存在编号与无权访问同一 403 同文案
    missing_obj = client.get("/objections/99999", headers=auth(outsider))
    forbidden_obj = client.get(f"/objections/{obj_id}", headers=auth(outsider))
    assert missing_obj.status_code == forbidden_obj.status_code == 403
    assert missing_obj.json() == forbidden_obj.json()


# ---------------------------------------------------------------------------
# 历史通知：失权不回收，凭据有效即可读/标记
# ---------------------------------------------------------------------------


def test_notifications_survive_permission_loss(client):
    owner = register(client, "owner")
    new = register(client, "new")
    w1, w2, w3 = (register(client, n) for n in ("w1", "w2", "w3"))
    w4 = register(client, "w4")
    doc_id = seal(client, owner, "通知保留正文 NOTIFY-KEEP-SECRET", ["w1", "w2", "w3"])["document_id"]

    # 替换 w3 -> w4：w3 收到 witness_replaced 通知后失去资料权限
    client.post(
        f"/documents/{doc_id}/witness-replacements",
        json={"old_witness": "w3", "new_witness": "w4"},
        headers=auth(owner),
    )
    # 交接 owner -> new：旧封存人收到 handover_confirmed 通知后失去资料权限
    _handover(client, owner, new, doc_id)

    for lost_key, etype in ((w3, "witness_replaced"), (owner, "handover_confirmed")):
        # 资料接口已失权
        assert client.get(f"/documents/{doc_id}", headers=auth(lost_key)).status_code == 403
        # 历史通知仍可读取、标记
        listed = client.get("/notifications", headers=auth(lost_key))
        assert listed.status_code == 200, listed.text
        mine = [n for n in listed.json()["notifications"] if n["event_type"] == etype]
        assert len(mine) == 1
        nid = mine[0]["notification_id"]
        marked = client.post(f"/notifications/{nid}/read", headers=auth(lost_key))
        assert marked.status_code == 200 and marked.json()["is_read"] is True
        # 通知不含正文/凭证/密钥
        assert "NOTIFY-KEEP-SECRET" not in listed.text


# ---------------------------------------------------------------------------
# 无账号入口保持原样：一次性阅览凭证兑换 + 可信公钥验真
# ---------------------------------------------------------------------------


def test_anonymous_view_pass_redeem_and_snapshot_verify_unchanged(client):
    owner = register(client, "owner")
    w = {n: register(client, n) for n in ("w1", "w2", "w3")}
    body = "无账号入口正文 ANON-ENTRY-SECRET"
    dg = digest_of(body)
    doc_id = seal(client, owner, body, ["w1", "w2", "w3"])["document_id"]
    req_id = client.post(
        f"/documents/{doc_id}/open-requests",
        json={"reason": "开封", "deadline": _iso(2)},
        headers=auth(owner),
    ).json()["request_id"]
    client.post(f"/open-requests/{req_id}/approve", json={"digest": dg}, headers=auth(w["w1"]))
    client.post(f"/open-requests/{req_id}/approve", json={"digest": dg}, headers=auth(w["w2"]))
    client.put(f"/documents/{doc_id}/purge", json={"purge_at": _iso(3)}, headers=auth(owner))

    # 签发一次性阅览凭证；外部复核人无需任何凭据兑换一次
    token = client.post(
        f"/documents/{doc_id}/view-passes", json={"expires_at": _iso(2)}, headers=auth(owner)
    ).json()["token"]
    redeemed = client.post("/view-passes/redeem", json={"token": token})
    assert redeemed.status_code == 200 and redeemed.json()["body"] == body
    assert client.post("/view-passes/redeem", json={"token": token}).status_code == 404

    # 可信公钥验真：无需凭据
    pub = client.get("/audit-snapshots/public-key")
    assert pub.status_code == 200
    pkg = client.post(f"/documents/{doc_id}/audit-snapshots", headers=auth(owner)).json()
    verified = client.post(
        "/audit-snapshots/verify",
        json={
            "snapshot": pkg["snapshot"],
            "signature": pkg["signature"],
            "public_key": pub.json()["public_key"],
        },
    )
    assert verified.status_code == 200 and verified.json()["valid"] is True


# ---------------------------------------------------------------------------
# 写事务内复核：交接在业务写等待写锁期间提交 -> 旧封存人 403 且整体回滚
# ---------------------------------------------------------------------------


def _simulate_handover_commit_during_lock_wait(monkeypatch, doc_id):
    """模拟“业务写等待写锁期间交接确认已提交”：在写事务首个到点结算钩子里
    把封存人转移给 new（随业务事务回滚而撤销，不影响库中真实状态）。"""
    import app.main as main_mod

    real = main_mod.resolve_due_waiting

    def patched(tx, now, request_id=None):
        tx.execute(
            "UPDATE documents SET owner_id ="
            " (SELECT id FROM users WHERE username = 'new') WHERE id = ?",
            (doc_id,),
        )
        return real(tx, now, request_id)

    monkeypatch.setattr(main_mod, "resolve_due_waiting", patched)


def test_open_request_rechecks_owner_inside_write_tx(quiet_client, monkeypatch):
    owner = register(quiet_client, "owner")
    register(quiet_client, "new")
    for n in ("w1", "w2", "w3"):
        register(quiet_client, n)
    doc_id = seal(quiet_client, owner, "锁内复核正文 INLOCK-OPEN", ["w1", "w2", "w3"])["document_id"]

    _simulate_handover_commit_during_lock_wait(monkeypatch, doc_id)
    r = quiet_client.post(
        f"/documents/{doc_id}/open-requests",
        json={"reason": "等待写锁期间被交接", "deadline": _iso(2)},
        headers=auth(owner),
    )
    assert r.status_code == 403, r.text
    # 整体回滚：无新请求、无业务审计、模拟的转移也随之撤销（仍是旧封存人）
    got = quiet_client.get(f"/documents/{doc_id}", headers=auth(owner)).json()
    assert got["status"] == "sealed" and "latest_open_request" not in got
    assert _audit_actions(quiet_client, owner, doc_id) == ["seal"]


def test_revoke_open_request_rechecks_owner_inside_write_tx(quiet_client, monkeypatch):
    owner = register(quiet_client, "owner")
    register(quiet_client, "new")
    for n in ("w1", "w2", "w3"):
        register(quiet_client, n)
    doc_id = seal(quiet_client, owner, "锁内复核正文 INLOCK-REVOKE", ["w1", "w2", "w3"])["document_id"]
    req_id = quiet_client.post(
        f"/documents/{doc_id}/open-requests",
        json={"reason": "待撤销", "deadline": _iso(2)},
        headers=auth(owner),
    ).json()["request_id"]

    _simulate_handover_commit_during_lock_wait(monkeypatch, doc_id)
    r = quiet_client.post(f"/open-requests/{req_id}/revoke", json={}, headers=auth(owner))
    assert r.status_code == 403, r.text
    got = quiet_client.get(f"/documents/{doc_id}", headers=auth(owner)).json()
    assert got["latest_open_request"]["status"] == "pending"
    assert "revoked" not in _audit_actions(quiet_client, owner, doc_id)


def test_replace_witness_rechecks_owner_inside_write_tx(quiet_client, monkeypatch):
    owner = register(quiet_client, "owner")
    register(quiet_client, "new")
    register(quiet_client, "w4")
    for n in ("w1", "w2", "w3"):
        register(quiet_client, n)
    doc_id = seal(quiet_client, owner, "锁内复核正文 INLOCK-REPLACE", ["w1", "w2", "w3"])["document_id"]

    _simulate_handover_commit_during_lock_wait(monkeypatch, doc_id)
    r = quiet_client.post(
        f"/documents/{doc_id}/witness-replacements",
        json={"old_witness": "w3", "new_witness": "w4"},
        headers=auth(owner),
    )
    assert r.status_code == 403, r.text
    got = quiet_client.get(f"/documents/{doc_id}", headers=auth(owner)).json()
    assert got["witnesses"] == ["w1", "w2", "w3"]
    assert "witness_replaced" not in _audit_actions(quiet_client, owner, doc_id)


def test_schedule_purge_rechecks_owner_inside_write_tx(quiet_client, monkeypatch):
    owner = register(quiet_client, "owner")
    register(quiet_client, "new")
    for n in ("w1", "w2", "w3"):
        register(quiet_client, n)
    doc_id = seal(quiet_client, owner, "锁内复核正文 INLOCK-PURGE", ["w1", "w2", "w3"])["document_id"]

    _simulate_handover_commit_during_lock_wait(monkeypatch, doc_id)
    r = quiet_client.put(
        f"/documents/{doc_id}/purge", json={"purge_at": _iso(3)}, headers=auth(owner)
    )
    assert r.status_code == 403, r.text
    got = quiet_client.get(f"/documents/{doc_id}", headers=auth(owner)).json()
    assert got["purge_at"] is None
    assert "purge_scheduled" not in _audit_actions(quiet_client, owner, doc_id)


def test_cancel_purge_rechecks_owner_inside_write_tx(quiet_client, monkeypatch):
    owner = register(quiet_client, "owner")
    register(quiet_client, "new")
    for n in ("w1", "w2", "w3"):
        register(quiet_client, n)
    doc_id = seal(quiet_client, owner, "锁内复核正文 INLOCK-CANCEL", ["w1", "w2", "w3"])["document_id"]
    purge_at = _iso(3)
    quiet_client.put(f"/documents/{doc_id}/purge", json={"purge_at": purge_at}, headers=auth(owner))

    _simulate_handover_commit_during_lock_wait(monkeypatch, doc_id)
    r = quiet_client.delete(f"/documents/{doc_id}/purge", headers=auth(owner))
    assert r.status_code == 403, r.text
    got = quiet_client.get(f"/documents/{doc_id}", headers=auth(owner)).json()
    assert got["purge_at"] == purge_at
    assert "purge_canceled" not in _audit_actions(quiet_client, owner, doc_id)


# ---------------------------------------------------------------------------
# 并发身份变更与操作按提交顺序裁定（真实 uvicorn + 多线程）
# ---------------------------------------------------------------------------


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_concurrent_handover_confirm_vs_open_request_commit_order(tmp_path, monkeypatch):
    """交接确认 vs 旧封存人提交开封请求：按 BEGIN IMMEDIATE 提交顺序裁定。

    - 确认先提交：开封申请在锁内复核到旧封存人已失权 -> 403，不落请求；
    - 申请先提交：确认随后把该请求置 invalidated（旧同意删除）。
    两种终态互斥且唯一，绝不出现“交接后旧封存人新立 pending 请求”。
    """
    import uvicorn

    from app.main import app

    db = tmp_path / "unified-race.db"
    monkeypatch.setenv("SEAL_DB_PATH", str(db))
    monkeypatch.setenv("SWEEP_INTERVAL_SECONDS", "1")
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"
    end = time.time() + 10
    while time.time() < end:
        try:
            if httpx.get(base + "/health", timeout=1).status_code == 200:
                break
        except Exception:
            time.sleep(0.1)
    else:  # pragma: no cover
        raise AssertionError("server did not start")

    try:
        with httpx.Client(timeout=10) as c:
            def reg(n):
                return c.post(base + "/register", json={"username": n}).json()["api_key"]

            owner, new = reg("r-owner"), reg("r-new")
            for n in ("r-w1", "r-w2", "r-w3"):
                reg(n)
            doc_id = c.post(
                base + "/documents",
                json={"body": "RACE-UNIFIED-SECRET", "witnesses": ["r-w1", "r-w2", "r-w3"]},
                headers={"X-API-Key": owner},
            ).json()["document_id"]
            inv_id = c.post(
                f"{base}/documents/{doc_id}/handover-invitations",
                json={"to_username": "r-new", "confirm_deadline": _iso(1)},
                headers={"X-API-Key": owner},
            ).json()["invitation_id"]

        barrier = threading.Barrier(2)

        def do_confirm():
            barrier.wait()
            with httpx.Client(timeout=10) as c:
                return c.post(
                    f"{base}/handover-invitations/{inv_id}/confirm",
                    headers={"X-API-Key": new},
                ).status_code

        def do_open_request():
            barrier.wait()
            with httpx.Client(timeout=10) as c:
                return c.post(
                    f"{base}/documents/{doc_id}/open-requests",
                    json={"reason": "赛跑申请", "deadline": _iso(2)},
                    headers={"X-API-Key": owner},
                ).status_code

        with ThreadPoolExecutor(max_workers=2) as pool:
            cf_code, or_code = list(pool.map(lambda f: f(), [do_confirm, do_open_request]))

        # 交接确认不受开封申请影响（资料仍 sealed、邀请 pending），必定成功
        assert cf_code == 200
        # 开封申请：要么先于确认提交（201），要么在锁内复核到失权（403）
        assert or_code in (201, 403)

        with httpx.Client(timeout=10) as c:
            # 旧封存人一律失权；新封存人立即得权
            assert c.get(f"{base}/documents/{doc_id}",
                         headers={"X-API-Key": owner}).status_code == 403
            got = c.get(f"{base}/documents/{doc_id}", headers={"X-API-Key": new}).json()
            assert got["status"] == "sealed" and "body" not in got
            latest = got.get("latest_open_request")
            if or_code == 403:
                # 确认先提交：旧封存人的申请被整体回滚，不存在新立的请求
                assert latest is None or latest["status"] != "pending"
            else:
                # 申请先提交：确认随即将其失效（旧同意删除）
                assert latest is not None and latest["status"] == "invalidated"
                assert latest["approval_count"] == 0
            records = c.get(f"{base}/documents/{doc_id}/audit",
                            headers={"X-API-Key": new}).json()["records"]
            actions = [r["action"] for r in records]
            assert actions.count("handover_confirmed") == 1
            assert actions.count("open_request_created") == (1 if or_code == 201 else 0)
    finally:
        server.should_exit = True
        thread.join(timeout=5)
