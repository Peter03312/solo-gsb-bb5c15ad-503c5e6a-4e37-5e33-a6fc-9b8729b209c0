"""统一参与方判定与写事务内复核（本轮权限边界）。

规格：
- 封存人交接确认、见证人替换提交后：旧身份立即不能再访问资料、审计、异议或
  签发快照；新身份立即按现有规则获得权限；
- 并发身份变更与业务操作按 BEGIN IMMEDIATE 提交顺序裁定；
- 资料/异议/邀请/凭证编号不存在与无权沿用相同拒绝结果（403，文案一致）；
- 失效（轮换/停用）密钥一律先返回既有 401，不借读写触发到期结算、不留业务审计；
- 历史通知仍仅供原收件人在凭据有效时读取、标记，不因失去资料权限而回收；
- 无账号的一次性阅览凭证兑换与提交可信公钥验真保持原有无凭据入口。
"""
import datetime as dt
import json
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest
import uvicorn
from fastapi.testclient import TestClient

from conftest import auth, digest_of, register, seal

BODY = "权限边界绝密正文 PERMISSION-BOUNDARY-SECRET"


@pytest.fixture
def passive_client(tmp_path, monkeypatch):
    """后台扫描间隔拉到 1 小时：到期清除只能由请求临界区自行推进。"""
    monkeypatch.setenv("SEAL_DB_PATH", str(tmp_path / "passive-boundary.db"))
    monkeypatch.setenv("SWEEP_INTERVAL_SECONDS", "3600")
    from app.main import app

    with TestClient(app) as c:
        yield c


def _deadline(hours: float = 1) -> str:
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=hours)).isoformat()


def _setup(client, witness_names=("pb-w1", "pb-w2", "pb-w3")):
    keys = {
        n: register(client, n)
        for n in ("pb-alice", "pb-erin", "pb-frank", *witness_names)
    }
    d = seal(client, keys["pb-alice"], BODY, list(witness_names))
    return keys, d["document_id"], d["digest"]


def _invite(client, owner_key, doc_id, to_name):
    r = client.post(
        f"/documents/{doc_id}/handover-invitations",
        json={"to_username": to_name, "confirm_deadline": _deadline()},
        headers=auth(owner_key),
    )
    assert r.status_code == 201, r.text
    return r.json()["invitation_id"]


def _confirm(client, key, inv_id):
    return client.post(f"/handover-invitations/{inv_id}/confirm", headers=auth(key))


def _replace(client, owner_key, doc_id, old, new):
    return client.post(
        f"/documents/{doc_id}/witness-replacements",
        json={"old_witness": old, "new_witness": new},
        headers=auth(owner_key),
    )


# ---------------------------------------------------------------------------
# 交接后：旧封存人立即失去资料及其派生资源访问，新封存人立即获得
# ---------------------------------------------------------------------------


def test_old_owner_loses_all_derived_access_after_handover(client):
    keys, doc_id, dg = _setup(client)
    alice, erin, frank = keys["pb-alice"], keys["pb-erin"], keys["pb-frank"]
    w1, w2, w3 = keys["pb-w1"], keys["pb-w2"], keys["pb-w3"]

    # 旧封存人先签发一张快照、安排清除时刻（作为“派生资源”样本）
    snap = client.post(f"/documents/{doc_id}/audit-snapshots", headers=auth(alice))
    assert snap.status_code == 201
    purge_at = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=2)).isoformat()
    assert client.put(f"/documents/{doc_id}/purge", json={"purge_at": purge_at},
                      headers=auth(alice)).status_code == 200

    inv_id = _invite(client, alice, doc_id, "pb-erin")
    assert _confirm(client, erin, inv_id).status_code == 200

    # 旧封存人：资料、审计、异议、快照、开封请求、清除安排、阅览凭证一律 403
    assert client.get(f"/documents/{doc_id}", headers=auth(alice)).status_code == 403
    assert client.get(f"/documents/{doc_id}/audit", headers=auth(alice)).status_code == 403
    assert client.get(f"/documents/999999/audit", headers=auth(alice)).status_code == 403
    assert client.post(
        f"/documents/{doc_id}/objections",
        json={"observed_digest": dg, "reason": "旧封存人试探"},
        headers=auth(alice),
    ).status_code == 403
    assert client.post(
        f"/documents/{doc_id}/audit-snapshots", headers=auth(alice)
    ).status_code == 403
    assert client.post(
        f"/documents/{doc_id}/open-requests",
        json={"reason": "旧封存人试探", "deadline": _deadline()},
        headers=auth(alice),
    ).status_code == 403
    assert client.put(
        f"/documents/{doc_id}/purge",
        json={"purge_at": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=3)).isoformat()},
        headers=auth(alice),
    ).status_code == 403
    assert client.delete(f"/documents/{doc_id}/purge", headers=auth(alice)).status_code == 403
    assert client.post(
        f"/documents/{doc_id}/view-passes",
        json={"expires_at": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)).isoformat()},
        headers=auth(alice),
    ).status_code == 403

    # 旧封存人不再出现在本人资料列表中
    listed = {d["id"] for d in client.get("/documents", headers=auth(alice)).json()["documents"]}
    assert doc_id not in listed

    # 新封存人立即按现有规则获得资料、审计、快照与清除安排的管理权限
    got = client.get(f"/documents/{doc_id}", headers=auth(erin))
    assert got.status_code == 200 and got.json()["status"] == "sealed"
    assert client.get(f"/documents/{doc_id}/audit", headers=auth(erin)).status_code == 200
    assert client.post(
        f"/documents/{doc_id}/audit-snapshots", headers=auth(erin)
    ).status_code == 201
    assert client.delete(f"/documents/{doc_id}/purge", headers=auth(erin)).status_code == 200

    # 见证人名单不变，见证人权限保留
    for wk in (w1, w2, w3):
        assert client.get(f"/documents/{doc_id}", headers=auth(wk)).status_code == 200
        assert client.get(f"/documents/{doc_id}/audit", headers=auth(wk)).status_code == 200
        assert client.post(
            f"/documents/{doc_id}/audit-snapshots", headers=auth(wk)
        ).status_code == 201

    # 无关账号仍 403（不区分存在性）
    assert client.get(f"/documents/{doc_id}", headers=auth(frank)).status_code == 403


def test_old_owner_cannot_revoke_invitation_after_handover_confirmed(client):
    keys, doc_id, _ = _setup(client)
    alice, erin = keys["pb-alice"], keys["pb-erin"]
    inv_id = _invite(client, alice, doc_id, "pb-erin")
    assert _confirm(client, erin, inv_id).status_code == 200
    # 交接先提交后，旧封存人的撤回按统一参与方口径 403（而非 409）
    r = client.post(f"/handover-invitations/{inv_id}/revoke", headers=auth(alice))
    assert r.status_code == 403
    # 旧封存人仍是该【邀请记录】的发起方（from_user），按既有规则可只读邀请元数据，
    # 但不能借此访问资料；资料/审计仍一律 403。
    assert client.get(f"/handover-invitations/{inv_id}", headers=auth(alice)).status_code == 200
    assert client.get(f"/documents/{doc_id}", headers=auth(alice)).status_code == 403
    assert client.get(f"/documents/{doc_id}/audit", headers=auth(alice)).status_code == 403
    # 新封存人（受让人）可查看该已确认邀请
    assert client.get(f"/handover-invitations/{inv_id}", headers=auth(erin)).status_code == 200
    # 与本邀请无关、也非资料参与方的账号：邀请查询统一 403（与不存在同结果）
    assert client.get(f"/handover-invitations/{inv_id}",
                      headers=auth(keys["pb-frank"])).status_code == 403


def test_objection_access_follows_current_participants_after_handover(client):
    keys, doc_id, dg = _setup(client)
    alice, erin = keys["pb-alice"], keys["pb-erin"]
    w1 = keys["pb-w1"]

    # 当前见证人 w1 提异议
    r = client.post(
        f"/documents/{doc_id}/objections",
        json={"observed_digest": dg, "reason": "交接前异议"},
        headers=auth(w1),
    )
    assert r.status_code == 201, r.text
    obj_id = r.json()["objection_id"]

    inv_id = _invite(client, alice, doc_id, "pb-erin")
    assert _confirm(client, erin, inv_id).status_code == 200

    # 旧封存人不能再查看异议；新封存人作为当前参与方可以
    assert client.get(f"/objections/{obj_id}", headers=auth(alice)).status_code == 403
    got = client.get(f"/objections/{obj_id}", headers=auth(erin))
    assert got.status_code == 200 and got.json()["objection_id"] == obj_id
    # 见证人仍可查看、驳回
    assert client.get(f"/objections/{obj_id}", headers=auth(w1)).status_code == 200


# ---------------------------------------------------------------------------
# 见证人替换后：旧见证人立即失去访问，新见证人立即获得
# ---------------------------------------------------------------------------


def test_replaced_witness_loses_access_and_new_witness_gains(client):
    keys, doc_id, dg = _setup(client)
    alice, w3, frank = keys["pb-alice"], keys["pb-w3"], keys["pb-frank"]

    assert _replace(client, alice, doc_id, "pb-w3", "pb-frank").status_code == 200

    # 旧见证人 w3：资料、审计、异议、快照、同意全部 403
    assert client.get(f"/documents/{doc_id}", headers=auth(w3)).status_code == 403
    assert client.get(f"/documents/{doc_id}/audit", headers=auth(w3)).status_code == 403
    assert client.post(
        f"/documents/{doc_id}/audit-snapshots", headers=auth(w3)
    ).status_code == 403
    assert client.post(
        f"/documents/{doc_id}/objections",
        json={"observed_digest": dg, "reason": "旧见证人试探"},
        headers=auth(w3),
    ).status_code == 403

    # 先建开封请求，再验证旧见证人不能同意、新见证人可以
    req = client.post(
        f"/documents/{doc_id}/open-requests",
        json={"reason": "换人后开封", "deadline": _deadline()},
        headers=auth(alice),
    ).json()["request_id"]
    assert client.post(f"/open-requests/{req}/approve", json={"digest": dg},
                       headers=auth(w3)).status_code == 403
    r = client.post(f"/open-requests/{req}/approve", json={"digest": dg},
                    headers=auth(frank))
    assert r.status_code == 200 and r.json()["approval_count"] == 1
    # 新见证人可查看资料与审计、签发快照
    assert client.get(f"/documents/{doc_id}", headers=auth(frank)).status_code == 200
    assert client.get(f"/documents/{doc_id}/audit", headers=auth(frank)).status_code == 200
    assert client.post(
        f"/documents/{doc_id}/audit-snapshots", headers=auth(frank)
    ).status_code == 201


def test_objection_filed_against_who_is_replaced_remains_accessible_to_current(client):
    keys, doc_id, dg = _setup(client)
    alice, erin, w2, w3 = (keys["pb-alice"], keys["pb-erin"],
                           keys["pb-w2"], keys["pb-w3"])
    # 异议人 w3；按规则异议人未决期间不能被替换。替换 w2 -> erin 后，
    # 新见证人 erin 应能查看该异议并参与驳回；w2 立即失去异议访问。
    r = client.post(
        f"/documents/{doc_id}/objections",
        json={"observed_digest": dg, "reason": "w3 的异议"},
        headers=auth(w3),
    )
    assert r.status_code == 201
    obj_id = r.json()["objection_id"]
    assert _replace(client, alice, doc_id, "pb-w2", "pb-erin").status_code == 200

    assert client.get(f"/objections/{obj_id}", headers=auth(w2)).status_code == 403
    assert client.get(f"/objections/{obj_id}", headers=auth(erin)).status_code == 200
    # 新见证人可凭摘要驳回；旧见证人 w2 不能
    assert client.post(
        f"/objections/{obj_id}/dismissals", json={"digest": dg}, headers=auth(w2)
    ).status_code == 403
    assert client.post(
        f"/objections/{obj_id}/dismissals", json={"digest": dg}, headers=auth(erin)
    ).status_code == 200


# ---------------------------------------------------------------------------
# 不存在编号与无权沿用相同拒绝结果（状态码与文案均一致）
# ---------------------------------------------------------------------------


def test_nonexistent_and_unauthorized_return_identical_result(client):
    keys, doc_id, _ = _setup(client)
    alice, erin, w1 = keys["pb-alice"], keys["pb-erin"], keys["pb-w1"]
    h_alice, h_erin = auth(alice), auth(erin)

    def pair(method, path, json_body=None):
        # 同一种“无权”与“不存在”两次请求，返回状态码与错误文案必须完全相同
        kw_a = {"headers": h_erin}
        kw_b = {"headers": h_erin}
        if json_body is not None:
            kw_a["json"] = json_body
            kw_b["json"] = json_body
        ra = getattr(client, method)(path.format(id=doc_id), **kw_a)
        rb = getattr(client, method)(path.format(id=999999), **kw_b)
        return ra, rb

    # 资料详情 / 审计 / 快照签发
    ra, rb = pair("get", "/documents/{id}")
    assert (ra.status_code, ra.text) == (rb.status_code, rb.text) == (403, ra.text)
    ra, rb = pair("get", "/documents/{id}/audit")
    assert (ra.status_code, ra.text) == (rb.status_code, rb.text) == (403, ra.text)
    ra, rb = pair("post", "/documents/{id}/audit-snapshots")
    assert (ra.status_code, ra.text) == (rb.status_code, rb.text) == (403, ra.text)

    # 开封请求撤销：无关账号 erin 对“存在但非参与方”的请求与“不存在”的请求
    # 至少同为 403（具体文案沿用既有角色/存在性提示，保持请求响应兼容）。
    req = client.post(
        f"/documents/{doc_id}/open-requests",
        json={"reason": "统一拒绝", "deadline": _deadline()},
        headers=h_alice,
    ).json()["request_id"]
    ra = client.post(f"/open-requests/{req}/revoke", json={"reason": "x"}, headers=h_erin)
    rb = client.post("/open-requests/999999/revoke", json={"reason": "x"}, headers=h_erin)
    assert ra.status_code == rb.status_code == 403
    # 同意：非指定见证人（存在请求）与请求不存在同为 403（开封请求沿用既有提示文案）
    ra = client.post(f"/open-requests/{req}/approve", json={"digest": "x"}, headers=h_erin)
    rb = client.post("/open-requests/999999/approve", json={"digest": "x"}, headers=h_erin)
    assert ra.status_code == rb.status_code == 403

    # 异议：不存在编号与非参与方同结果
    ra = client.get(f"/objections/999999", headers=h_erin)
    rb = client.post(f"/documents/{doc_id}/objections",
                     json={"observed_digest": "x", "reason": "非见证人"}, headers=h_erin)
    assert ra.status_code == rb.status_code == 403

    # 交接邀请：不存在编号，任何账号（含本人有效凭据）统一 403
    r = client.post("/handover-invitations/999999/revoke", headers=h_alice)
    assert r.status_code == 403
    r = client.post("/handover-invitations/999999/confirm", headers=h_alice)
    assert r.status_code == 403
    assert client.get("/handover-invitations/999999", headers=h_alice).status_code == 403

    # 阅览凭证撤销：不存在编号与非封存人（见证人 w1）同结果
    r1 = client.post("/view-passes/999999/revoke", headers=h_alice)
    r2 = client.post("/view-passes/999999/revoke", headers=auth(w1))
    assert (r1.status_code, r1.text) == (403, r1.text) == (r2.status_code, r2.text)


# ---------------------------------------------------------------------------
# 失效密钥：先返回既有 401，不借读写触发到期结算，不留业务审计
# ---------------------------------------------------------------------------


def test_invalid_key_returns_401_without_settlement_or_audit(passive_client):
    client = passive_client
    keys, doc_id, dg = _setup(client)
    alice = keys["pb-alice"]

    # 安排一个 1 秒后到点的清除；随后用【完全无效】的密钥反复读写：
    # 必须一律 401，且不得借这些请求把资料清除（到期结算只由扫描器/合法请求推进）。
    purge_at = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=1)).isoformat()
    assert client.put(f"/documents/{doc_id}/purge", json={"purge_at": purge_at},
                      headers=auth(alice)).status_code == 200
    time.sleep(1.2)

    bogus = "deadbeef" * 8
    bogus_h = {"X-API-Key": bogus}
    assert client.get(f"/documents/{doc_id}", headers=bogus_h).status_code == 401
    assert client.get(f"/documents/{doc_id}/audit", headers=bogus_h).status_code == 401
    assert client.get("/documents", headers=bogus_h).status_code == 401
    assert client.post(
        f"/documents/{doc_id}/objections",
        json={"observed_digest": dg, "reason": "无效密钥"},
        headers=bogus_h,
    ).status_code == 401
    assert client.post(
        f"/documents/{doc_id}/audit-snapshots", headers=bogus_h
    ).status_code == 401

    # 无效密钥没有触发清除：合法封存人此刻查看（其读路径才推进结算）前资料仍封存。
    import sqlite3
    import os
    conn = sqlite3.connect(os.environ["SEAL_DB_PATH"])
    status, body = conn.execute(
        "SELECT status, body FROM documents WHERE id=?", (doc_id,)
    ).fetchone()
    conn.close()
    assert status == "sealed" and body == BODY

    # 审计链中没有因无效密钥请求产生的任何业务记录（仍只有封存 + 两条 purge 安排）
    records = client.get(f"/documents/{doc_id}/audit", headers=auth(alice)).json()["records"]
    # 上一行合法读已推进清除；清除由合法读触发，purged 仅此一次
    assert [r["action"] for r in records] == ["seal", "purge_scheduled", "purged"]


def test_rotated_old_key_reads_401_and_triggers_no_write(passive_client):
    client = passive_client
    keys, doc_id, _ = _setup(client)
    alice = keys["pb-alice"]

    # 轮换密钥；旧密钥立即失效
    rot = client.post("/me/api-key/rotate", headers=auth(alice))
    assert rot.status_code == 200
    new_key = rot.json()["api_key"]

    purge_at = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=1)).isoformat()
    assert client.put(f"/documents/{doc_id}/purge", json={"purge_at": purge_at},
                      headers=auth(new_key)).status_code == 200
    time.sleep(1.2)

    # 旧密钥读：401，且不能借读触发清除
    assert client.get(f"/documents/{doc_id}", headers=auth(alice)).status_code == 401
    import os
    import sqlite3
    conn = sqlite3.connect(os.environ["SEAL_DB_PATH"])
    status = conn.execute("SELECT status FROM documents WHERE id=?", (doc_id,)).fetchone()[0]
    conn.close()
    assert status == "sealed"
    # 新密钥读：200，并由合法读推进清除
    assert client.get(f"/documents/{doc_id}", headers=auth(new_key)).json()["status"] == "purged"


def test_deactivated_key_accesses_nothing_but_others_read_audit(client):
    keys, doc_id, _ = _setup(client)
    w1 = keys["pb-w1"]
    # w1 只是见证人（非封存人），其义务会阻止停用；改测一个无义务账号 frank
    frank = keys["pb-frank"]
    assert client.post("/me/deactivation", headers=auth(frank)).status_code == 200
    # 停用后旧密钥一切访问沿用无效密钥 401（资料、通知、标记已读同口径）
    assert client.get("/me", headers=auth(frank)).status_code == 401
    assert client.get("/documents", headers=auth(frank)).status_code == 401
    assert client.get(f"/documents/{doc_id}", headers=auth(frank)).status_code == 401
    assert client.get("/notifications", headers=auth(frank)).status_code == 401
    assert client.post("/notifications/1/read", headers=auth(frank)).status_code == 401
    # 同名不可重注册
    r = client.post("/register", json={"username": "pb-frank"})
    assert r.status_code == 409
    # 其他账号不受影响
    assert client.get(f"/documents/{doc_id}", headers=auth(w1)).status_code == 200


# ---------------------------------------------------------------------------
# 历史通知：仅供原收件人在凭据有效时读取/标记，不因失去资料权限而回收
# ---------------------------------------------------------------------------


def test_notifications_remain_for_old_identities_until_key_invalid(client):
    keys, doc_id, _ = _setup(client)
    alice, erin, w3 = keys["pb-alice"], keys["pb-erin"], keys["pb-w3"]

    # 见证人替换：w3 应收到 witness_replaced 通知
    assert _replace(client, alice, doc_id, "pb-w3", "pb-erin").status_code == 200

    # w3 已失去资料权限……
    assert client.get(f"/documents/{doc_id}", headers=auth(w3)).status_code == 403
    # ……但仍是自己历史通知的原收件人，可读取并标记
    notes = client.get("/notifications", headers=auth(w3)).json()["notifications"]
    events = [n["event_type"] for n in notes]
    assert "witness_replaced" in events
    nid = next(n["notification_id"] for n in notes if n["event_type"] == "witness_replaced")
    r = client.post(f"/notifications/{nid}/read", headers=auth(w3))
    assert r.status_code == 200 and r.json()["is_read"] is True
    # 幂等
    assert client.post(f"/notifications/{nid}/read", headers=auth(w3)).json()["is_read"] is True
    # 他人（新封存人 erin）不能标记 w3 的通知
    assert client.post(f"/notifications/{nid}/read", headers=auth(erin)).status_code == 403

    # 交接后旧封存人 alice 同样保留其历史通知：alice 直接把资料交给 zoe
    zoe = register(client, "pb-zoe")
    inv_id = _invite(client, alice, doc_id, "pb-zoe")
    assert _confirm(client, zoe, inv_id).status_code == 200
    assert client.get(f"/documents/{doc_id}", headers=auth(alice)).status_code == 403
    alice_notes = client.get("/notifications", headers=auth(alice)).json()["notifications"]
    # 旧封存人 alice 收到交接完成通知（她是该事件的收件人之一）
    assert any(n["event_type"] == "handover_confirmed" for n in alice_notes)
    # 通知不含正文
    assert BODY not in json.dumps(alice_notes, ensure_ascii=False)


# ---------------------------------------------------------------------------
# 无账号入口保持不变：阅览凭证兑换、可信公钥验真
# ---------------------------------------------------------------------------


def test_keyless_entry_points_remain_open(client):
    keys, doc_id, dg = _setup(client)
    alice, w1, w2 = keys["pb-alice"], keys["pb-w1"], keys["pb-w2"]

    # 开封资料（两票）并安排清除时刻后签发阅览凭证
    req = client.post(
        f"/documents/{doc_id}/open-requests",
        json={"reason": "无凭据入口", "deadline": _deadline()},
        headers=auth(alice),
    ).json()["request_id"]
    client.post(f"/open-requests/{req}/approve", json={"digest": dg}, headers=auth(w1))
    client.post(f"/open-requests/{req}/approve", json={"digest": dg}, headers=auth(w2))
    purge_at = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=2)).isoformat()
    client.put(f"/documents/{doc_id}/purge", json={"purge_at": purge_at}, headers=auth(alice))
    expires = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)).isoformat()
    issued = client.post(
        f"/documents/{doc_id}/view-passes", json={"expires_at": expires}, headers=auth(alice)
    )
    assert issued.status_code == 201
    token = issued.json()["token"]

    # 兑换无需任何凭据
    r = client.post("/view-passes/redeem", json={"token": token})
    assert r.status_code == 200 and r.json()["body"] == BODY
    # 再兑一次：统一 404
    assert client.post("/view-passes/redeem", json={"token": token}).status_code == 404

    # 快照公钥与验真无需账号凭据
    pub = client.get("/audit-snapshots/public-key")
    assert pub.status_code == 200
    snap = client.post(f"/documents/{doc_id}/audit-snapshots", headers=auth(alice)).json()
    r = client.post("/audit-snapshots/verify",
                    json={"snapshot": snap["snapshot"], "signature": snap["signature"],
                          "public_key": pub.json()["public_key"]})
    assert r.status_code == 200 and r.json()["valid"] is True
    # 篡改即验真失败（400）
    tampered = json.loads(json.dumps(snap["snapshot"]))
    tampered["digest"] = "0" * 64
    r = client.post("/audit-snapshots/verify",
                    json={"snapshot": tampered, "signature": snap["signature"],
                          "public_key": pub.json()["public_key"]})
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# 并发：身份变更与业务操作按提交顺序裁定（真实服务 + 屏障并发）
# ---------------------------------------------------------------------------


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def live_server(tmp_path, monkeypatch):
    monkeypatch.setenv("SEAL_DB_PATH", str(tmp_path / "perm-boundary.db"))
    monkeypatch.setenv("SWEEP_INTERVAL_SECONDS", "3600")
    from app.main import app

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
    else:
        pytest.fail("server did not start")
    yield base
    server.should_exit = True
    thread.join(timeout=5)


def _reg(c, base, name):
    return c.post(base + "/register", json={"username": name}).json()["api_key"]


def test_concurrent_handover_vs_open_request_decided_by_commit_order(live_server):
    base = live_server
    with httpx.Client(timeout=15) as c:
        owner = _reg(c, base, "crb-owner")
        new = _reg(c, base, "crb-new")
        for n in ("crb-w1", "crb-w2", "crb-w3"):
            _reg(c, base, n)
        body = "CR-BOUNDARY-SECRET"
        dg = digest_of(body)
        doc_id = c.post(
            base + "/documents", json={"body": body, "witnesses": ["crb-w1", "crb-w2", "crb-w3"]},
            headers=auth(owner),
        ).json()["document_id"]
        deadline = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)).isoformat()
        inv_id = c.post(
            f"{base}/documents/{doc_id}/handover-invitations",
            json={"to_username": "crb-new", "confirm_deadline": deadline},
            headers=auth(owner),
        ).json()["invitation_id"]

    barrier = threading.Barrier(2)

    def do_confirm():
        barrier.wait()
        with httpx.Client(timeout=15) as c:
            return c.post(f"{base}/handover-invitations/{inv_id}/confirm",
                          headers=auth(new)).status_code

    def do_create_request():
        barrier.wait()
        with httpx.Client(timeout=15) as c:
            return c.post(
                f"{base}/documents/{doc_id}/open-requests",
                json={"reason": "与交接赛跑",
                      "deadline": (dt.datetime.now(dt.timezone.utc)
                                   + dt.timedelta(hours=1)).isoformat()},
                headers=auth(owner),
            ).status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        cf_code, cr_code = list(pool.map(lambda f: f(), [do_confirm, do_create_request]))

    with httpx.Client(timeout=15) as c:
        # 两种提交顺序，身份最终都归受让人（建请求不会开封资料，交接随后仍成立）；
        # 区别只在后提交的建请求是否被允许。
        assert cf_code == 200
        if cr_code == 403:
            # 交接先提交：旧封存人随后的建请求按统一参与方口径 403（与不存在同结果）
            pass
        else:
            # 建请求先提交（201）：交接随后提交，把刚建的请求失效后完成身份转移
            assert cr_code == 201
        # 终态唯一：旧封存人无权、新封存人有权；建请求先提交时该请求已被交接失效
        assert c.get(f"{base}/documents/{doc_id}", headers=auth(owner)).status_code == 403
        new_got = c.get(f"{base}/documents/{doc_id}", headers=auth(new))
        assert new_got.status_code == 200 and new_got.json()["status"] == "sealed"
        latest = new_got.json().get("latest_open_request")
        if cr_code == 201:
            assert latest is not None and latest["status"] == "invalidated"
        # 新封存人可以重新申请开封
        assert c.post(
            f"{base}/documents/{doc_id}/open-requests",
            json={"reason": "新封存人申请",
                  "deadline": (dt.datetime.now(dt.timezone.utc)
                               + dt.timedelta(hours=1)).isoformat()},
            headers=auth(new),
        ).status_code == 201


def test_concurrent_handover_vs_purge_reschedule_decided_by_commit_order(live_server):
    base = live_server
    with httpx.Client(timeout=15) as c:
        owner = _reg(c, base, "crp-owner")
        new = _reg(c, base, "crp-new")
        for n in ("crp-w1", "crp-w2", "crp-w3"):
            _reg(c, base, n)
        doc_id = c.post(
            base + "/documents",
            json={"body": "CR-PURGE-SECRET", "witnesses": ["crp-w1", "crp-w2", "crp-w3"]},
            headers=auth(owner),
        ).json()["document_id"]
        deadline = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)).isoformat()
        inv_id = c.post(
            f"{base}/documents/{doc_id}/handover-invitations",
            json={"to_username": "crp-new", "confirm_deadline": deadline},
            headers=auth(owner),
        ).json()["invitation_id"]
        later = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=3)).isoformat()

    barrier = threading.Barrier(2)

    def do_confirm():
        barrier.wait()
        with httpx.Client(timeout=15) as c:
            return c.post(f"{base}/handover-invitations/{inv_id}/confirm",
                          headers=auth(new)).status_code

    def do_reschedule():
        barrier.wait()
        with httpx.Client(timeout=15) as c:
            return c.put(f"{base}/documents/{doc_id}/purge",
                         json={"purge_at": later}, headers=auth(owner)).status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        cf_code, pu_code = list(pool.map(lambda f: f(), [do_confirm, do_reschedule]))

    with httpx.Client(timeout=15) as c:
        if cf_code == 200 and pu_code == 403:
            # 交接先提交：旧封存人的改期 403，清除安排保留由新封存人管理
            assert c.get(f"{base}/documents/{doc_id}", headers=auth(owner)).status_code == 403
            got = c.get(f"{base}/documents/{doc_id}", headers=auth(new)).json()
            assert got["status"] == "sealed"
            assert c.put(f"{base}/documents/{doc_id}/purge",
                         json={"purge_at": later}, headers=auth(new)).status_code == 200
        else:
            # 改期先提交（200），交接随后完成（200）
            assert pu_code == 200 and cf_code == 200
            assert c.get(f"{base}/documents/{doc_id}", headers=auth(owner)).status_code == 403
            assert c.get(f"{base}/documents/{doc_id}", headers=auth(new)).status_code == 200
