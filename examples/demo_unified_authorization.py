#!/usr/bin/env python3
"""统一参与方判定与写事务内复核（本轮权限边界）端到端示例（纯标准库）。

覆盖：
1) 封存人交接确认提交后：旧封存人访问资料/审计/异议/签发快照与全部封存人
   写操作一律 403（不区分资料是否存在），新封存人立即按现有规则获得权限；
2) 见证人替换提交后：旧见证人失去资料/审计/快照签发/同意权限（403），
   新见证人立即获得；
3) 账号停用提交后：旧密钥的一切访问沿用既有 401（与随机假密钥同文案）；
4) 资料/异议编号不存在与无权沿用同一 403 文案；
5) 历史通知仍仅供原收件人在凭据有效时读取/标记，不因失去资料权限而回收；
6) 无账号的一次性阅览凭证兑换与可信公钥验真保持原有入口。

用法: python examples/demo_unified_authorization.py [base_url]
"""
import datetime as dt
import json
import sys
import urllib.error
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"


def call(method: str, path: str, key: str | None = None, payload: dict | None = None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        BASE + path, data=data, method=method,
        headers={"Content-Type": "application/json", **({"X-API-Key": key} if key else {})},
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def in_hours(h: float) -> str:
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=h)).isoformat()


def show(title: str, status: int, body) -> None:
    print(f"-- {title} -> {status}")
    print("   " + json.dumps(body, ensure_ascii=False))


def main() -> None:
    users = {}
    for name in ["u-alice", "u-bob", "u-carol", "u-dave", "u-erin", "u-frank"]:
        _, body = call("POST", "/register", payload={"username": name})
        users[name] = body["api_key"]
    alice, bob, carol, dave, erin, frank = (
        users[n] for n in ["u-alice", "u-bob", "u-carol", "u-dave", "u-erin", "u-frank"]
    )

    # ------------------------------------------------------------------
    # 场景 1：交接确认提交后，旧封存人立即失权、新封存人立即得权
    # ------------------------------------------------------------------
    print("== 场景 1：交接提交后的身份即时生效 ==")
    _, sealed = call("POST", "/documents", alice,
                     {"body": "统一权限示例正文 UNIFIED-AUTHZ-SECRET",
                      "witnesses": ["u-bob", "u-carol", "u-dave"]})
    doc1, digest1 = sealed["document_id"], sealed["digest"]

    _, inv = call("POST", f"/documents/{doc1}/handover-invitations", alice,
                  {"to_username": "u-erin", "confirm_deadline": in_hours(1)})
    status, resp = call("POST", f"/handover-invitations/{inv['invitation_id']}/confirm", erin)
    show("erin 确认交接", status, resp)
    assert status == 200 and resp["current_owner"] == "u-erin"

    # 旧封存人：资料/审计/快照签发/写操作统一 403（与资料不存在同一拒绝结果）
    for title, method, path, payload in [
        ("旧封存人查资料", "GET", f"/documents/{doc1}", None),
        ("旧封存人查审计", "GET", f"/documents/{doc1}/audit", None),
        ("旧封存人签发快照", "POST", f"/documents/{doc1}/audit-snapshots", None),
        ("旧封存人提交开封请求", "POST", f"/documents/{doc1}/open-requests",
         {"reason": "旧身份申请", "deadline": in_hours(2)}),
        ("旧封存人安排清除", "PUT", f"/documents/{doc1}/purge", {"purge_at": in_hours(3)}),
        ("旧封存人替换见证人", "POST", f"/documents/{doc1}/witness-replacements",
         {"old_witness": "u-dave", "new_witness": "u-frank"}),
    ]:
        s, b = call(method, path, alice, payload)
        print(f"-- {title} -> {s}")
        assert s == 403 and b == {"detail": "无权访问该资料或资料不存在"}, (title, s, b)
    # 与“资料不存在”同一拒绝结果（状态码与文案都不可区分）
    s_missing, b_missing = call("GET", "/documents/99999", alice)
    s_forbid, b_forbid = call("GET", f"/documents/{doc1}", alice)
    assert (s_missing, b_missing) == (s_forbid, b_forbid) == (403, b_missing)

    # 新封存人：立即按现有规则获得权限
    s, got = call("GET", f"/documents/{doc1}", erin)
    show("新封存人查资料（开封前无正文）", s, got)
    assert s == 200 and got["status"] == "sealed" and "body" not in got
    s, req = call("POST", f"/documents/{doc1}/open-requests", erin,
                  {"reason": "新封存人申请", "deadline": in_hours(2)})
    assert s == 201
    req1 = req["request_id"]

    # ------------------------------------------------------------------
    # 场景 2：见证人替换提交后，旧见证人失权、新见证人得权
    # ------------------------------------------------------------------
    print("== 场景 2：替换提交后的见证人身份即时生效 ==")
    s, resp = call("POST", f"/documents/{doc1}/witness-replacements", erin,
                   {"old_witness": "u-dave", "new_witness": "u-frank"})
    show("新封存人替换见证人 dave -> frank", s, resp)
    assert s == 200 and resp["witnesses"] == ["u-bob", "u-carol", "u-frank"]

    s, _ = call("GET", f"/documents/{doc1}", dave)
    print(f"-- 旧见证人 dave 查资料 -> {s}")
    assert s == 403
    s, _ = call("POST", f"/open-requests/{req1}/approve", dave, {"digest": digest1})
    print(f"-- 旧见证人 dave 同意 -> {s}")
    assert s == 403
    s, _ = call("POST", f"/documents/{doc1}/audit-snapshots", dave)
    print(f"-- 旧见证人 dave 签发快照 -> {s}")
    assert s == 403

    s, ok = call("POST", f"/open-requests/{req1}/approve", frank, {"digest": digest1})
    show("新见证人 frank 补票同意", s, ok)
    assert s == 200 and ok["approval_count"] == 1
    s, _ = call("POST", f"/documents/{doc1}/audit-snapshots", frank)
    print(f"-- 新见证人 frank 签发快照 -> {s}")
    assert s == 201

    # ------------------------------------------------------------------
    # 场景 3：历史通知不因失去资料权限而回收
    # ------------------------------------------------------------------
    print("== 场景 3：失权后历史通知仍可读、可标记 ==")
    # dave（被替换的旧见证人）与 alice（交接后的旧封存人）凭有效密钥读通知
    for who, key, etype in ((("u-dave"), dave, "witness_replaced"),
                            (("u-alice"), alice, "handover_confirmed")):
        s, inbox = call("GET", "/notifications", key)
        mine = [n for n in inbox["notifications"] if n["event_type"] == etype]
        print(f"-- {who} 读取本人通知 -> {s}（{len(mine)} 条 {etype}）")
        assert s == 200 and len(mine) == 1
        nid = mine[0]["notification_id"]
        s, marked = call("POST", f"/notifications/{nid}/read", key)
        show(f"{who} 标记已读", s, marked)
        assert s == 200 and marked["is_read"] is True
        # 通知不含正文，不能借此访问资料
        assert "UNIFIED-AUTHZ-SECRET" not in json.dumps(inbox, ensure_ascii=False)

    # ------------------------------------------------------------------
    # 场景 4：账号停用提交后，旧密钥一律既有 401
    # ------------------------------------------------------------------
    print("== 场景 4：停用提交后旧密钥 401（与假密钥同文案） ==")
    _, nobody = call("POST", "/register", payload={"username": "u-gone"})
    gone = nobody["api_key"]
    s, resp = call("POST", "/me/deactivation", gone)
    show("u-gone 停用账号", s, resp)
    assert s == 200 and resp["status"] == "deactivated"
    s, body = call("GET", f"/documents/{doc1}", gone)
    print(f"-- 停用后旧密钥查资料 -> {s} {body}")
    assert s == 401 and body == {"detail": "凭据无效"}
    s2, body2 = call("GET", f"/documents/{doc1}", "0" * 64)
    assert (s, body) == (s2, body2)  # 与随机假密钥完全不可区分

    # ------------------------------------------------------------------
    # 场景 5：无账号入口保持原样（一次性阅览凭证兑换 + 可信公钥验真）
    # ------------------------------------------------------------------
    print("== 场景 5：无账号入口不变 ==")
    # 新封存人把资料两票开封并安排清除，再签发一次性阅览凭证
    call("POST", f"/open-requests/{req1}/approve", bob, {"digest": digest1})
    _, opened = call("GET", f"/documents/{doc1}", erin)
    assert opened["status"] == "opened"
    call("PUT", f"/documents/{doc1}/purge", erin, {"purge_at": in_hours(3)})
    _, issued = call("POST", f"/documents/{doc1}/view-passes", erin,
                     {"expires_at": in_hours(2)})
    s, redeemed = call("POST", "/view-passes/redeem", None, {"token": issued["token"]})
    show("外部复核人无凭据兑换阅览凭证", s, redeemed)
    assert s == 200 and redeemed["body"] == "统一权限示例正文 UNIFIED-AUTHZ-SECRET"
    s, _ = call("POST", "/view-passes/redeem", None, {"token": issued["token"]})
    print(f"-- 再次兑换 -> {s}（统一 404）")
    assert s == 404

    _, pub = call("GET", "/audit-snapshots/public-key")
    _, pkg = call("POST", f"/documents/{doc1}/audit-snapshots", erin)
    s, verified = call("POST", "/audit-snapshots/verify", None,
                       {"snapshot": pkg["snapshot"], "signature": pkg["signature"],
                        "public_key": pub["public_key"]})
    show("复核人凭事先信任的公钥离线验真", s, verified)
    assert s == 200 and verified["valid"] is True

    print("\n全部统一权限边界示例断言通过。")


if __name__ == "__main__":
    main()
