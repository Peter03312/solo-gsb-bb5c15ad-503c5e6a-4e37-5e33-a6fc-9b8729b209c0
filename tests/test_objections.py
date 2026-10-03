"""见证人异议功能测试。

规则要点（规格）：
- 当前指定见证人可在开封前凭现有密钥提交资料编号、所见摘要和非空理由，
  取得异议编号与状态；仅当前见证人可提出；同一资料同时至多一件未决异议；
  摘要不符拒绝且不留记录（不插异议、不写审计、不通知）；
- 受理异议时进行中的开封请求及旧同意失效，并阻止新开封申请；
- 若两票已齐且最早开封时刻已到，须先按现有规则开封，此时异议被拒绝；
- 异议人可撤回；其余两名当前见证人可各凭原摘要驳回一次，两票齐才解除拦截，
  重复、摘要不符或非当前人员的驳回不计票；
- 未决期间不得替换异议人；替换其他见证人时旧人的驳回票失效；
  交接后异议继续约束新封存人；
- 到期清除照常执行，清除后异议归档（archived）且不可再操作；
- 异议受理与终结留审计并通知当时参与方；查询异议不泄露正文；
- 非参与者与不存在编号沿用统一 403 拒绝语义；
- 并发异议、开封与见证变更按写锁内结算后的状态裁定。
"""
import datetime as dt
import time

from conftest import auth, digest_of, register, seal

BODY = "见证人异议绝密资料 OBJECTION-SECRET"


def _deadline(minutes: int = 60) -> str:
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=minutes)).isoformat()


def _setup(client, names=("owner", "w1", "w2", "w3", "w4")):
    keys = {n: register(client, n) for n in names}
    d = seal(client, keys["owner"], BODY, ["w1", "w2", "w3"])
    return keys, d["document_id"], d["digest"]


def _file(client, key, doc_id, dg, *, reason="摘要与我所见不符", digest=None):
    return client.post(
        f"/documents/{doc_id}/objections",
        json={"observed_digest": digest or dg, "reason": reason},
        headers=auth(key),
    )


def _withdraw(client, key, obj_id):
    return client.post(f"/objections/{obj_id}/withdraw", headers=auth(key))


def _dismiss(client, key, obj_id, dg):
    return client.post(
        f"/objections/{obj_id}/dismissals",
        json={"digest": dg},
        headers=auth(key),
    )


def _open_request(client, owner_key, doc_id, *, minutes=60, earliest=None, reason="异议测试"):
    payload = {"reason": reason, "deadline": _deadline(minutes)}
    if earliest is not None:
        payload["earliest_open_at"] = (
            dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=earliest)
        ).isoformat()
    return client.post(
        f"/documents/{doc_id}/open-requests", json=payload, headers=auth(owner_key)
    )


def _approve(client, key, req, dg):
    return client.post(
        f"/open-requests/{req}/approve", json={"digest": dg}, headers=auth(key)
    )


def _audit_actions(client, owner_key, doc_id):
    records = client.get(f"/documents/{doc_id}/audit", headers=auth(owner_key)).json()["records"]
    return [r["action"] for r in records]


# ---------------------------------------------------------------------------
# 受理：基本成功、校验与不留记录
# ---------------------------------------------------------------------------


def test_witness_files_objection(client):
    keys, doc_id, dg = _setup(client)
    r = _file(client, keys["w1"], doc_id, dg)
    assert r.status_code == 201, r.text
    data = r.json()
    assert data["status"] == "pending"
    assert data["document_id"] == doc_id
    assert data["objector_username"] == "w1"
    assert data["observed_digest"] == dg
    assert data["sealed_digest"] == dg
    assert data["dismissal_count"] == 0
    assert data["required"] == 2
    assert data["old_open_request"] is None
    assert "objection_id" in data and "created_at" in data
    # 响应不含正文
    assert BODY not in r.text

    # GET /documents 反映未决异议
    got = client.get(f"/documents/{doc_id}", headers=auth(keys["owner"])).json()
    assert got["pending_objection"]["objection_id"] == data["objection_id"]
    assert got["pending_objection"]["objector_username"] == "w1"


def test_only_current_witness_can_file(client):
    keys, doc_id, dg = _setup(client)
    # 封存人本人不能提异议（403）
    assert _file(client, keys["owner"], doc_id, dg).status_code == 403
    # 外人 / 不存在编号统一 403
    outsider = register(client, "outsider")
    assert _file(client, outsider, doc_id, dg).status_code == 403
    assert _file(client, outsider, 9999, dg).status_code == 403
    # 无/错密钥 401
    assert client.post(
        f"/documents/{doc_id}/objections",
        json={"observed_digest": dg, "reason": "x"},
    ).status_code == 401
    assert client.post(
        f"/documents/{doc_id}/objections",
        json={"observed_digest": dg, "reason": "x"},
        headers=auth("deadbeef"),
    ).status_code == 401
    # 空理由 / 缺字段 422
    assert _file(client, keys["w1"], doc_id, dg, reason="").status_code == 422
    assert client.post(
        f"/documents/{doc_id}/objections",
        json={"observed_digest": dg},
        headers=auth(keys["w1"]),
    ).status_code == 422


def test_digest_mismatch_rejected_without_record(client):
    keys, doc_id, dg = _setup(client)
    wrong = digest_of("别的正文")
    r = _file(client, keys["w1"], doc_id, dg, digest=wrong)
    assert r.status_code == 409
    assert BODY not in r.text
    # 不留任何记录：无异议、无审计、无通知
    got = client.get(f"/documents/{doc_id}", headers=auth(keys["owner"])).json()
    assert got["pending_objection"] is None
    actions = _audit_actions(client, keys["owner"], doc_id)
    assert not any(a.startswith("objection") for a in actions)
    notifs = client.get("/notifications", headers=auth(keys["w1"])).json()["notifications"]
    assert not any(n["event_type"].startswith("objection") for n in notifs)
    # 之后用正确摘要仍可提
    assert _file(client, keys["w1"], doc_id, dg).status_code == 201


def test_only_one_pending_objection(client):
    keys, doc_id, dg = _setup(client)
    assert _file(client, keys["w1"], doc_id, dg).status_code == 201
    # 其他见证人对同一资料再提 -> 409 且不留记录
    r = _file(client, keys["w2"], doc_id, dg)
    assert r.status_code == 409
    # 查询仍只有一件（w1 的）
    got = client.get(f"/documents/{doc_id}", headers=auth(keys["owner"])).json()
    assert got["pending_objection"]["objector_username"] == "w1"


# ---------------------------------------------------------------------------
# 受理即失效进行中开封请求 + 旧同意，并阻止新开封申请
# ---------------------------------------------------------------------------


def test_filing_invalidates_active_request_and_blocks_new(client):
    keys, doc_id, dg = _setup(client)
    req = _open_request(client, keys["owner"], doc_id).json()["request_id"]
    assert _approve(client, keys["w1"], req, dg).json()["approval_count"] == 1

    r = _file(client, keys["w2"], doc_id, dg)
    assert r.status_code == 201, r.text
    old = r.json()["old_open_request"]
    assert old["status"] == "invalidated"
    assert old["request_id"] == req
    assert old["approval_count"] == 0

    got = client.get(f"/documents/{doc_id}", headers=auth(keys["owner"])).json()
    assert got["latest_open_request"]["status"] == "invalidated"
    assert got["latest_open_request"]["approval_count"] == 0
    # 资料仍封存、无正文
    assert got["status"] == "sealed" and "body" not in got

    # 旧同意已删除，且阻止新开封申请
    assert _approve(client, keys["w1"], req, dg).status_code == 409
    r = _open_request(client, keys["owner"], doc_id)
    assert r.status_code == 409
    assert BODY not in r.text


# ---------------------------------------------------------------------------
# 两票已齐且最早开封时刻已到：先开封，异议被拒绝
# ---------------------------------------------------------------------------


def _passive(tmp_path, monkeypatch):
    monkeypatch.setenv("SEAL_DB_PATH", str(tmp_path / "passive-obj.db"))
    monkeypatch.setenv("SWEEP_INTERVAL_SECONDS", "3600")
    from app.main import app
    from fastapi.testclient import TestClient

    return TestClient(app)


def _wait_until(ts_iso: str) -> None:
    target = dt.datetime.fromisoformat(ts_iso)
    while dt.datetime.now(dt.timezone.utc) < target:
        time.sleep(0.01)


def test_due_open_takes_precedence_over_objection(tmp_path, monkeypatch):
    c = _passive(tmp_path, monkeypatch)
    with c:
        keys = {n: register(c, n) for n in ("owner", "w1", "w2", "w3", "w4")}
        d = seal(c, keys["owner"], BODY, ["w1", "w2", "w3"])
        doc_id, dg = d["document_id"], d["digest"]
        payload = {
            "reason": "到点异议赛跑",
            "deadline": _deadline(60),
            "earliest_open_at": (
                dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=1)
            ).isoformat(),
        }
        req = c.post(
            f"/documents/{doc_id}/open-requests", json=payload, headers=auth(keys["owner"])
        ).json()["request_id"]
        _approve(c, keys["w1"], req, dg)
        _approve(c, keys["w2"], req, dg)  # 两票齐，待到点 -> waiting
        _wait_until(
            c.get(f"/documents/{doc_id}", headers=auth(keys["owner"])).json()[
                "latest_open_request"]["earliest_open_at"]
        )
        time.sleep(0.05)
        # 后台不扫描：异议事务必须先确定性开封，再拒绝异议
        r = _file(c, keys["w3"], doc_id, dg)
        assert r.status_code == 409, r.text
        assert BODY not in r.text
        got = c.get(f"/documents/{doc_id}", headers=auth(keys["owner"])).json()
        assert got["status"] == "opened" and got["body"] == BODY
        # 已开封资料不返回未决异议字段（异议未被受理）
        assert "pending_objection" not in got
        # 没有任何异议行/审计（开封审计有，异议审计无）
        actions = _audit_actions(c, keys["owner"], doc_id)
        assert "opened" in actions and "objection_filed" not in actions


# ---------------------------------------------------------------------------
# 撤回
# ---------------------------------------------------------------------------


def test_objector_can_withdraw_and_unblock(client):
    keys, doc_id, dg = _setup(client)
    obj_id = _file(client, keys["w1"], doc_id, dg).json()["objection_id"]
    r = _withdraw(client, keys["w1"], obj_id)
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "withdrawn"
    assert r.json()["resolved_at"] is not None
    # 解除拦截：可重新申请开封
    req = _open_request(client, keys["owner"], doc_id).json()["request_id"]
    assert _approve(client, keys["w1"], req, dg).json()["approval_count"] == 1
    # 已撤回不能再撤回/驳回
    assert _withdraw(client, keys["w1"], obj_id).status_code == 409
    assert _dismiss(client, keys["w2"], obj_id, dg).status_code == 409
    # 终结后可提新异议（不再有未决；该异议会失效当前进行中的开封请求）
    assert _file(client, keys["w2"], doc_id, dg).status_code == 201


def test_withdraw_permissions(client):
    keys, doc_id, dg = _setup(client)
    obj_id = _file(client, keys["w1"], doc_id, dg).json()["objection_id"]
    # 其他见证人/封存人/外人/不存在编号都不能撤回
    assert _withdraw(client, keys["w2"], obj_id).status_code == 403
    assert _withdraw(client, keys["owner"], obj_id).status_code == 403
    outsider = register(client, "outsider2")
    assert _withdraw(client, outsider, obj_id).status_code == 403
    assert _withdraw(client, keys["w1"], 9999).status_code == 403


# ---------------------------------------------------------------------------
# 驳回：两票齐解除拦截；重复/摘要不符/非当前人员不计票
# ---------------------------------------------------------------------------


def test_filing_while_waiting_before_earliest_invalidates(client):
    keys, doc_id, dg = _setup(client)
    # 最早开封时刻在 1 小时后：两票提前集齐只进入 waiting，不到点不开封
    req = _open_request(client, keys["owner"], doc_id, minutes=120, earliest=3600).json()["request_id"]
    assert _approve(client, keys["w1"], req, dg).json()["status"] == "pending"
    assert _approve(client, keys["w2"], req, dg).json()["status"] == "waiting"
    # 未投票的 w3 在最早开封时刻前提异议：请求失效（不开封），异议受理
    r = _file(client, keys["w3"], doc_id, dg)
    assert r.status_code == 201, r.text
    assert r.json()["old_open_request"]["status"] == "invalidated"
    got = client.get(f"/documents/{doc_id}", headers=auth(keys["owner"])).json()
    assert got["status"] == "sealed" and "body" not in got
    assert got["latest_open_request"]["status"] == "invalidated"


def test_two_dismissals_resolve_objection(client):
    keys, doc_id, dg = _setup(client)
    obj = _file(client, keys["w1"], doc_id, dg).json()
    obj_id = obj["objection_id"]
    # 第一票
    r = _dismiss(client, keys["w2"], obj_id, dg)
    assert r.status_code == 200
    assert r.json()["status"] == "pending" and r.json()["dismissal_count"] == 1
    # 异议人本人不能驳回
    assert _dismiss(client, keys["w1"], obj_id, dg).status_code == 403
    # 第二票 -> dismissed
    r = _dismiss(client, keys["w3"], obj_id, dg)
    assert r.status_code == 200
    assert r.json()["status"] == "dismissed"
    assert r.json()["dismissal_count"] == 2
    assert r.json()["resolved_at"] is not None
    # 解除拦截：可重新开封
    req = _open_request(client, keys["owner"], doc_id).json()["request_id"]
    assert _approve(client, keys["w1"], req, dg).status_code == 200
    assert _approve(client, keys["w2"], req, dg).json()["status"] == "opened"


def test_dismiss_repeat_and_bad_digest_not_counted(client):
    keys, doc_id, dg = _setup(client)
    obj_id = _file(client, keys["w1"], doc_id, dg).json()["objection_id"]
    wrong = digest_of("其他")
    # 摘要不符 -> 409 不计票
    assert _dismiss(client, keys["w2"], obj_id, wrong).status_code == 409
    got = client.get(f"/objections/{obj_id}", headers=auth(keys["w2"])).json()
    assert got["dismissal_count"] == 0
    # 正确摘要计一票；重复 -> 409 仍只一票
    assert _dismiss(client, keys["w2"], obj_id, dg).json()["dismissal_count"] == 1
    assert _dismiss(client, keys["w2"], obj_id, dg).status_code == 409
    assert _dismiss(client, keys["w2"], obj_id, wrong).status_code == 409
    got = client.get(f"/objections/{obj_id}", headers=auth(keys["w2"])).json()
    assert got["dismissal_count"] == 1
    # 非当前人员（外人、封存人）-> 403
    outsider = register(client, "outsider3")
    assert _dismiss(client, outsider, obj_id, dg).status_code == 403
    assert _dismiss(client, keys["owner"], obj_id, dg).status_code == 403
    assert _dismiss(client, outsider, 9999, dg).status_code == 403
    # 第二票（另一见证人）仍可驳回终结
    assert _dismiss(client, keys["w3"], obj_id, dg).json()["status"] == "dismissed"


# ---------------------------------------------------------------------------
# 查询异议：参与方可见，不泄露正文；非参与方/不存在 403
# ---------------------------------------------------------------------------


def test_get_objection_visibility_and_no_body(client):
    keys, doc_id, dg = _setup(client)
    obj_id = _file(client, keys["w1"], doc_id, dg).json()["objection_id"]
    # 三名见证人 + 封存人可见
    for who in ("owner", "w1", "w2", "w3"):
        r = client.get(f"/objections/{obj_id}", headers=auth(keys[who]))
        assert r.status_code == 200, r.text
        assert BODY not in r.text
    # 外人 / 不存在编号统一 403
    outsider = register(client, "outsider4")
    assert client.get(f"/objections/{obj_id}", headers=auth(outsider)).status_code == 403
    assert client.get("/objections/9999", headers=auth(keys["owner"])).status_code == 403
    assert client.get(f"/objections/{obj_id}").status_code == 401


# ---------------------------------------------------------------------------
# 未决期间不得替换异议人；替换其他见证人旧驳回票失效
# ---------------------------------------------------------------------------


def test_cannot_replace_objector_while_pending(client):
    keys, doc_id, dg = _setup(client)
    obj_id = _file(client, keys["w1"], doc_id, dg).json()["objection_id"]
    r = client.post(
        f"/documents/{doc_id}/witness-replacements",
        json={"old_witness": "w1", "new_witness": "w4"},
        headers=auth(keys["owner"]),
    )
    assert r.status_code == 409, r.text
    # 名单不变
    got = client.get(f"/documents/{doc_id}", headers=auth(keys["owner"])).json()
    assert got["witnesses"] == ["w1", "w2", "w3"]
    # 异议仍在
    assert client.get(f"/objections/{obj_id}", headers=auth(keys["w2"])).json()["status"] == "pending"


def test_replacing_other_witness_voids_their_dismissal(client):
    keys, doc_id, dg = _setup(client)
    obj_id = _file(client, keys["w1"], doc_id, dg).json()["objection_id"]
    # w2 投一张驳回票
    assert _dismiss(client, keys["w2"], obj_id, dg).json()["dismissal_count"] == 1
    # 把另一名见证人 w3 换成 w4（非异议人、非投票人）不影响票
    r = client.post(
        f"/documents/{doc_id}/witness-replacements",
        json={"old_witness": "w3", "new_witness": "w4"},
        headers=auth(keys["owner"]),
    )
    assert r.status_code == 200
    got = client.get(f"/objections/{obj_id}", headers=auth(keys["owner"])).json()
    assert got["dismissal_count"] == 1
    # w4 作为新当前见证人可凭原摘要驳回第二票 -> dismissed
    assert _dismiss(client, keys["w4"], obj_id, dg).json()["status"] == "dismissed"

    # 再来一轮：w1 提异议、w2 驳回，然后替换掉投票人 w2 -> 票失效
    obj_id2 = _file(client, keys["w1"], doc_id, dg).json()["objection_id"]
    assert _dismiss(client, keys["w2"], obj_id2, dg).json()["dismissal_count"] == 1
    r = client.post(
        f"/documents/{doc_id}/witness-replacements",
        json={"old_witness": "w2", "new_witness": "w3"},
        headers=auth(keys["owner"]),
    )
    assert r.status_code == 200
    got = client.get(f"/objections/{obj_id2}", headers=auth(keys["owner"])).json()
    assert got["dismissal_count"] == 0
    # 旧 w2 已不在名单，驳回被拒（403）；w3 可重新驳回
    assert _dismiss(client, keys["w2"], obj_id2, dg).status_code == 403
    assert _dismiss(client, keys["w3"], obj_id2, dg).json()["dismissal_count"] == 1


# ---------------------------------------------------------------------------
# 交接后异议继续约束新封存人
# ---------------------------------------------------------------------------


def test_objection_survives_handover(client):
    keys, doc_id, dg = _setup(client, names=("owner", "w1", "w2", "w3", "w4"))
    erin_key = register(client, "erin")
    obj_id = _file(client, keys["w1"], doc_id, dg).json()["objection_id"]
    # 异议拦截开封：新开封申请被拒（409）
    assert _open_request(client, keys["owner"], doc_id).status_code == 409
    # 但交接仍可发起/确认（异议不随交接消失，继续约束新封存人）

    inv = client.post(
        f"/documents/{doc_id}/handover-invitations",
        json={"to_username": "erin", "confirm_deadline": _deadline(60)},
        headers=auth(keys["owner"]),
    ).json()["invitation_id"]
    r = client.post(f"/handover-invitations/{inv}/confirm", headers=auth(erin_key))
    assert r.status_code == 200, r.text
    assert r.json()["current_owner"] == "erin"
    assert r.json()["old_open_request"] is None  # 异议受理时本就无进行中请求

    # 异议仍未决：新封存人不能开封，旧封存人失去权限；新封存人可见异议
    assert _open_request(client, erin_key, doc_id).status_code == 409
    got = client.get(f"/documents/{doc_id}", headers=auth(erin_key)).json()
    assert got["pending_objection"]["objection_id"] == obj_id
    assert client.get(f"/documents/{doc_id}", headers=auth(keys["owner"])).status_code == 403
    got = client.get(f"/objections/{obj_id}", headers=auth(erin_key)).json()
    assert got["status"] == "pending"
    # 见证人 w2/w3 仍可凭原摘要驳回（名单未变），两票齐解除拦截
    assert _dismiss(client, keys["w2"], obj_id, dg).json()["dismissal_count"] == 1
    assert _dismiss(client, keys["w3"], obj_id, dg).json()["status"] == "dismissed"
    # 解除后新封存人可申请开封
    req2 = _open_request(client, erin_key, doc_id)
    assert req2.status_code == 201, req2.text

# ---------------------------------------------------------------------------
# 到期清除：异议归档且不可再操作；清除先提交再拒绝
# ---------------------------------------------------------------------------


def test_purge_archives_objection_and_blocks_further_ops(client):
    keys, doc_id, dg = _setup(client)
    obj_id = _file(client, keys["w1"], doc_id, dg).json()["objection_id"]
    purge_at = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=1)).isoformat()
    r = client.put(
        f"/documents/{doc_id}/purge",
        json={"purge_at": purge_at},
        headers=auth(keys["owner"]),
    )
    assert r.status_code == 200
    time.sleep(1.15)
    # 查询触发确定性清除，异议随之归档
    got = client.get(f"/documents/{doc_id}", headers=auth(keys["owner"])).json()
    assert got["status"] == "purged" and "body" not in got
    obj = client.get(f"/objections/{obj_id}", headers=auth(keys["w2"])).json()
    assert obj["status"] == "archived"
    assert obj["resolved_at"] is not None
    # 归档后不可撤回/驳回
    assert _withdraw(client, keys["w1"], obj_id).status_code == 409
    assert _dismiss(client, keys["w2"], obj_id, dg).status_code == 409
    # 已清除资料不能再提异议
    assert _file(client, keys["w2"], doc_id, dg).status_code == 409
    # 审计含 objection_filed 与 objection_archived
    actions = _audit_actions(client, keys["owner"], doc_id)
    assert "objection_filed" in actions
    assert "objection_archived" in actions
    assert "purged" in actions


def test_withdraw_after_purge_commits_first_then_rejects(client):
    keys, doc_id, dg = _setup(client)
    obj_id = _file(client, keys["w1"], doc_id, dg).json()["objection_id"]
    purge_at = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=1)).isoformat()
    client.put(
        f"/documents/{doc_id}/purge", json={"purge_at": purge_at}, headers=auth(keys["owner"])
    )
    time.sleep(1.15)
    # 撤回临界区先清除归档，再拒绝撤回（409）
    r = _withdraw(client, keys["w1"], obj_id)
    assert r.status_code == 409
    obj = client.get(f"/objections/{obj_id}", headers=auth(keys["owner"])).json()
    assert obj["status"] == "archived"
    got = client.get(f"/documents/{doc_id}", headers=auth(keys["owner"])).json()
    assert got["status"] == "purged"


# ---------------------------------------------------------------------------
# 审计与通知
# ---------------------------------------------------------------------------


def test_audit_and_notifications_on_file_and_resolution(client):
    keys, doc_id, dg = _setup(client)
    obj_id = _file(client, keys["w1"], doc_id, dg).json()["objection_id"]

    def objection_notifs(key):
        rows = client.get("/notifications", headers=auth(key)).json()["notifications"]
        return [n["event_type"] for n in rows if n["event_type"].startswith("objection")]

    # 受理：四名当时参与方各收到一条 objection_filed
    for who in ("owner", "w1", "w2", "w3"):
        assert objection_notifs(keys[who]) == ["objection_filed"]

    # 审计：seal 之后有 request_invalidated?（无进行中请求）只有 objection_filed
    actions = _audit_actions(client, keys["owner"], doc_id)
    assert actions[-1] == "objection_filed"

    # 两票驳回 -> dismissed 通知
    _dismiss(client, keys["w2"], obj_id, dg)
    _dismiss(client, keys["w3"], obj_id, dg)
    for who in ("owner", "w1", "w2", "w3"):
        types = objection_notifs(keys[who])
        assert types == ["objection_filed", "objection_dismissed"]
    actions = _audit_actions(client, keys["owner"], doc_id)
    assert "objection_dismissal" in actions
    assert actions[-1] == "objection_dismissed"


def test_withdraw_notification(client):
    keys, doc_id, dg = _setup(client)
    obj_id = _file(client, keys["w1"], doc_id, dg).json()["objection_id"]
    _withdraw(client, keys["w1"], obj_id)
    types = [
        n["event_type"]
        for n in client.get("/notifications", headers=auth(keys["owner"])).json()["notifications"]
        if n["event_type"].startswith("objection")
    ]
    assert types == ["objection_filed", "objection_withdrawn"]


# ---------------------------------------------------------------------------
# 并发：同时提异议只产生一件；异议 vs 第二票同意赛跑只有一个终态
# ---------------------------------------------------------------------------


def test_concurrent_objections_single_outcome(tmp_path, monkeypatch):
    import socket
    import threading
    from concurrent.futures import ThreadPoolExecutor

    import httpx
    import uvicorn

    monkeypatch.setenv("SEAL_DB_PATH", str(tmp_path / "concurrent-obj.db"))
    monkeypatch.setenv("SWEEP_INTERVAL_SECONDS", "60")
    from app.main import app

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
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
        raise AssertionError("server did not start")

    try:
        with httpx.Client(timeout=10) as c:
            def reg(n):
                return c.post(base + "/register", json={"username": n}).json()["api_key"]

            owner, w1, w2, w3 = (reg(n) for n in ("o1", "a1", "a2", "a3"))
            import hashlib

            body = "并发异议正文 CONCURRENT-OBJECTION"
            dg = hashlib.sha256(body.encode()).hexdigest()
            doc_id = c.post(
                base + "/documents",
                json={"body": body, "witnesses": ["a1", "a2", "a3"]},
                headers={"X-API-Key": owner},
            ).json()["document_id"]

        barrier = threading.Barrier(2)

        def file_obj(key):
            barrier.wait()
            with httpx.Client(timeout=10) as c:
                return c.post(
                    f"{base}/documents/{doc_id}/objections",
                    json={"observed_digest": dg, "reason": "并发异议"},
                    headers={"X-API-Key": key},
                ).status_code

        with ThreadPoolExecutor(max_workers=2) as pool:
            c1, c2 = list(pool.map(lambda f: f(), [lambda: file_obj(w1), lambda: file_obj(w2)]))

        assert sorted([c1, c2]) == [201, 409]
        with httpx.Client(timeout=10) as c:
            import sqlite3

            db_path = str(tmp_path / "concurrent-obj.db")
            conn = sqlite3.connect(db_path)
            n = conn.execute(
                "SELECT COUNT(*) FROM objections WHERE document_id=? AND status='pending'",
                (doc_id,),
            ).fetchone()[0]
            conn.close()
            assert n == 1
    finally:
        server.should_exit = True
        thread.join(timeout=5)


def test_concurrent_second_approval_vs_objection_single_outcome(tmp_path, monkeypatch):
    import socket
    import threading
    from concurrent.futures import ThreadPoolExecutor

    import httpx
    import uvicorn

    monkeypatch.setenv("SEAL_DB_PATH", str(tmp_path / "concurrent-ao.db"))
    monkeypatch.setenv("SWEEP_INTERVAL_SECONDS", "60")
    from app.main import app

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
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
        raise AssertionError("server did not start")

    try:
        with httpx.Client(timeout=10) as c:
            def reg(n):
                return c.post(base + "/register", json={"username": n}).json()["api_key"]

            owner, w1, w2, w3 = (reg(n) for n in ("bo", "b1", "b2", "b3"))
            import hashlib

            body = "并发同意异议赛跑 CONCURRENT-AO"
            dg = hashlib.sha256(body.encode()).hexdigest()
            doc_id = c.post(
                base + "/documents",
                json={"body": body, "witnesses": ["b1", "b2", "b3"]},
                headers={"X-API-Key": owner},
            ).json()["document_id"]
            deadline = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=2)).isoformat()
            req_id = c.post(
                f"{base}/documents/{doc_id}/open-requests",
                json={"reason": "赛跑", "deadline": deadline},
                headers={"X-API-Key": owner},
            ).json()["request_id"]
            # w1 一票；第二票（w2）与 w3 的异议同时
            assert c.post(
                f"{base}/open-requests/{req_id}/approve",
                json={"digest": dg}, headers={"X-API-Key": w1},
            ).status_code == 200

        barrier = threading.Barrier(2)

        def approve_w2():
            barrier.wait()
            with httpx.Client(timeout=10) as c:
                return c.post(
                    f"{base}/open-requests/{req_id}/approve",
                    json={"digest": dg}, headers={"X-API-Key": w2},
                )

        def object_w3():
            barrier.wait()
            with httpx.Client(timeout=10) as c:
                return c.post(
                    f"{base}/documents/{doc_id}/objections",
                    json={"observed_digest": dg, "reason": "赛跑异议"},
                    headers={"X-API-Key": w3},
                )

        with ThreadPoolExecutor(max_workers=2) as pool:
            ap_future = pool.submit(approve_w2)
            ob_future = pool.submit(object_w3)
            ap = ap_future.result()
            ob = ob_future.result()

        with httpx.Client(timeout=10) as c:
            h = {"X-API-Key": owner}
            got = c.get(f"{base}/documents/{doc_id}", headers=h).json()
            records = c.get(f"{base}/documents/{doc_id}/audit", headers=h).json()["records"]
            actions = [r["action"] for r in records]
            if got["status"] == "opened":
                # 第二票先提交开封：异议被拒（409），无异议记录
                assert ap.status_code == 200
                assert ob.status_code == 409
                assert "objection_filed" not in actions
                assert got["body"] == body
            else:
                # 异议先受理：请求失效，第二票被拒；资料仍封存
                assert ob.status_code == 201
                assert ap.status_code == 409
                assert got["status"] == "sealed" and "body" not in got
                assert "objection_filed" in actions
                assert "request_invalidated" in actions
                assert got["pending_objection"] is not None
    finally:
        server.should_exit = True
        thread.join(timeout=5)
