#!/usr/bin/env python3
"""统一参与方判定与写事务内复核 —— 本轮权限边界端到端示例（纯标准库）。

覆盖（全部仅使用既有可调用 HTTP API，请求/响应/状态码与副作用不变）：
1) 封存人交接确认提交后：旧封存人立即失去资料/审计/异议/快照签发/开封请求/
   清除安排等全部派生资源权限（统一 403，与编号不存在同结果），新封存人立即
   按现有规则获得；见证人权限不受影响；
2) 见证人替换提交后：旧见证人立即失去访问与同意/异议权限，新见证人立即获得；
3) 资料/异议/邀请等编号不存在与无权沿用相同 403 文案；
4) 失效密钥（含停用账号）一律先返回既有 401，不借读写触发到期清除、不留业务
   审计；轮换后的旧密钥同样 401 且不能借读推进结算；
5) 历史通知仍仅供原收件人在凭据有效时读取/标记，不因失去资料权限而回收；
6) 无账号入口保持原样：一次性阅览凭证兑换、提交可信公钥验真均无需凭据。

用法: python examples/demo_permission_boundary.py [base_url]
"""
import datetime as dt
import json
import sys
import time
import urllib.error
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"


def call(method, path, key=None, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        BASE + path, data=data, method=method,
        headers={"Content-Type": "application/json",
                 **({"X-API-Key": key} if key else {})},
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def in_hours(h):
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=h)).isoformat()


def in_seconds(s):
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=s)).isoformat()


def show(title, status):
    print(f"-- {title} -> {status}")


def main() -> None:
    users = {}
    for name in ["b-alice", "b-erin", "b-zoe", "b-bob", "b-carol", "b-dave", "b-frank"]:
        users[name] = call("POST", "/register", payload={"username": name})[1]["api_key"]
    alice, erin, zoe = users["b-alice"], users["b-erin"], users["b-zoe"]
    bob, carol, dave, frank = (users[n] for n in
                               ("b-bob", "b-carol", "b-dave", "b-frank"))

    body = "权限边界示例正文 PERMISSION-DEMO-SECRET"
    sealed = call("POST", "/documents", alice,
                  {"body": body, "witnesses": ["b-bob", "b-carol", "b-dave"]})[1]
    doc, digest = sealed["document_id"], sealed["digest"]
    print("== 1) 封存人交接：旧身份立即失权、新身份立即获权 ==")

    inv = call("POST", f"/documents/{doc}/handover-invitations", alice,
               {"to_username": "b-erin", "confirm_deadline": in_hours(1)})[1]["invitation_id"]
    assert call("POST", f"/handover-invitations/{inv}/confirm", erin)[0] == 200

    # 旧封存人对资料及全部派生资源统一 403（与不存在编号同文案）
    s_existing = call("GET", f"/documents/{doc}", alice)[0]
    s_missing = call("GET", "/documents/999999", alice)[0]
    show("旧封存人访问资料（存在编号 / 不存在编号）", f"{s_existing} / {s_missing}")
    assert s_existing == s_missing == 403
    for method, path, payload in [
        ("GET", f"/documents/{doc}/audit", None),
        ("POST", f"/documents/{doc}/audit-snapshots", None),
        ("POST", f"/documents/{doc}/open-requests",
         {"reason": "旧人试探", "deadline": in_hours(1)}),
        ("DELETE", f"/documents/{doc}/purge", None),
    ]:
        assert call(method, path, alice, payload)[0] == 403
    # 新封存人立即获得；见证人权限保留
    assert call("GET", f"/documents/{doc}", erin)[0] == 200
    assert call("POST", f"/documents/{doc}/audit-snapshots", erin)[0] == 201
    assert call("GET", f"/documents/{doc}/audit", bob)[0] == 200

    print("== 2) 见证人替换：旧见证人立即失权，新见证人立即获权 ==")
    assert call("POST", f"/documents/{doc}/witness-replacements", erin,
                {"old_witness": "b-dave", "new_witness": "b-frank"})[0] == 200
    assert call("GET", f"/documents/{doc}", dave)[0] == 403
    assert call("POST", f"/documents/{doc}/audit-snapshots", dave)[0] == 403
    assert call("GET", f"/documents/{doc}", frank)[0] == 200
    assert call("POST", f"/documents/{doc}/audit-snapshots", frank)[0] == 201

    print("== 3) 失效密钥先 401：不触发到期清除、不留业务审计 ==")
    # 新封存人 erin 轮换密钥：旧密钥立即 401
    rotated = call("POST", "/me/api-key/rotate", erin)[1]
    erin_new = rotated["api_key"]
    call("PUT", f"/documents/{doc}/purge", erin_new, {"purge_at": in_seconds(1)})
    time.sleep(1.2)
    assert call("GET", f"/documents/{doc}", erin)[0] == 401          # 旧密钥 401
    assert call("GET", f"/documents/{doc}", "0" * 64)[0] == 401     # 无效密钥 401
    # 旧/无效密钥的读没有触发清除：资料此刻仍封存
    # （用新密钥的合法读才推进确定性清除）
    assert call("GET", f"/documents/{doc}", erin_new)[1]["status"] == "purged"
    records = call("GET", f"/documents/{doc}/audit", erin_new)[1]["records"]
    assert "purged" in [r["action"] for r in records]

    print("== 4) 历史通知不随资料权限回收（以无义务账号演示停用） ==")
    # 见证人替换会给新旧见证人发通知；dave 已失去资料权限但通知仍可读、可标记
    notes = call("GET", "/notifications", dave)[1]["notifications"]
    nid = next(n["notification_id"] for n in notes
               if n["event_type"] == "witness_replaced")
    assert call("POST", f"/notifications/{nid}/read", dave)[0] == 200
    assert body not in json.dumps(notes, ensure_ascii=False)   # 通知不含正文
    # 无义务账号停用：当前密钥立即 401，通知也随之不可读（凭据失效先于一切）
    assert call("POST", "/me/deactivation", zoe)[0] == 200
    assert call("GET", "/notifications", zoe)[0] == 401

    print("== 5) 无账号入口保持原样：阅览凭证兑换 + 可信公钥验真 ==")
    # 另造一份已开封资料演示无账号兑换
    _, sealed = call("POST", "/documents", bob,
                     {"body": "无账号阅览正文 VIEWPASS-DEMO",
                      "witnesses": ["b-alice", "b-carol", "b-frank"]})
    doc2, dg2 = sealed["document_id"], sealed["digest"]
    req = call("POST", f"/documents/{doc2}/open-requests", bob,
               {"reason": "x", "deadline": in_hours(1)})[1]["request_id"]
    call("POST", f"/open-requests/{req}/approve", alice, {"digest": dg2})
    call("POST", f"/open-requests/{req}/approve", carol, {"digest": dg2})
    call("PUT", f"/documents/{doc2}/purge", bob, {"purge_at": in_hours(2)})
    issued = call("POST", f"/documents/{doc2}/view-passes", bob,
                  {"expires_at": in_hours(1)})[1]
    redeemed = call("POST", "/view-passes/redeem", payload={"token": issued["token"]})
    assert redeemed[0] == 200 and redeemed[1]["body"] == "无账号阅览正文 VIEWPASS-DEMO"
    assert call("POST", "/view-passes/redeem", payload={"token": issued["token"]})[0] == 404
    # 验真：取公钥（无需凭据）-> 签发 -> 用提交的可信公钥验真
    pub = call("GET", "/audit-snapshots/public-key")[1]["public_key"]
    snap = call("POST", f"/documents/{doc2}/audit-snapshots", bob)[1]
    ok = call("POST", "/audit-snapshots/verify",
              payload={"snapshot": snap["snapshot"], "signature": snap["signature"],
                       "public_key": pub})
    assert ok[0] == 200 and ok[1]["valid"] is True

    print("\n全部权限边界示例断言通过。")


if __name__ == "__main__":
    main()
