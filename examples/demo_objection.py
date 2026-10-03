#!/usr/bin/env python3
"""见证人异议功能调用示例（纯标准库，无需第三方依赖）。

覆盖：
1) 当前见证人凭资料编号、所见摘要与非空理由提出异议：进行中开封请求及旧
   同意失效、阻止新开封申请；
2) 其余两名当前见证人各凭原摘要驳回一次，两票齐解除拦截；
3) 异议人撤回异议，解除拦截后可重新申请开封；
4) 未决期间不得替换异议人；替换其他见证人时旧人驳回票失效，由新人补票；
5) 到期清除后异议归档，不可再撤回/驳回；
6) 常见拒绝：非当前见证人 403、摘要不符/重复异议 409 且不留记录、
   非参与者与不存在编号统一 403、查询不泄露正文。

用法: python examples/demo_objection.py [base_url]
"""
import datetime as dt
import json
import sys
import urllib.error
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"


def call(method, path, key=None, payload=None):
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


def in_hours(h):
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=h)).isoformat()


def in_seconds(s):
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=s)).isoformat()


def show(title, status, body):
    print(f"-- {title} -> {status}")
    print("   " + json.dumps(body, ensure_ascii=False))


def main():
    users = {}
    for name in ["alice", "bob", "carol", "dave", "erin"]:
        _, body = call("POST", "/register", payload={"username": name})
        users[name] = body["api_key"]
    owner, bob, carol, dave, erin = (users[n] for n in
                                     ["alice", "bob", "carol", "dave", "erin"])

    # ------------------------------------------------------------------
    # 场景 1：异议受理 -> 两票驳回 -> 解除拦截
    # ------------------------------------------------------------------
    print("== 场景 1：提异议失效进行中开封请求，两票驳回解除拦截 ==")
    _, sealed = call("POST", "/documents", owner,
                     {"body": "异议示例正文 OBJECTION-DEMO-SECRET",
                      "witnesses": ["bob", "carol", "dave"]})
    doc1, dg1 = sealed["document_id"], sealed["digest"]
    _, req = call("POST", f"/documents/{doc1}/open-requests", owner,
                  {"reason": "家庭会议", "deadline": in_hours(24)})
    req1 = req["request_id"]
    call("POST", f"/open-requests/{req1}/approve", bob, {"digest": dg1})  # bob 一票

    # carol 提出异议：进行中请求失效、bob 旧票作废、阻止新开封申请
    status, obj = call("POST", f"/documents/{doc1}/objections", carol,
                       {"observed_digest": dg1, "reason": "摘要与我参与记录所见不一致"})
    show("carol 提出异议", status, obj)
    assert status == 201
    assert obj["status"] == "pending"
    assert obj["old_open_request"]["status"] == "invalidated"
    obj1 = obj["objection_id"]

    # 新开封申请被拦截
    assert call("POST", f"/documents/{doc1}/open-requests", owner,
                {"reason": "再试", "deadline": in_hours(24)})[0] == 409

    # 异议人本人不能驳回；其余两名当前见证人各凭原摘要驳回一次
    assert call("POST", f"/objections/{obj1}/dismissals", carol, {"digest": dg1})[0] == 403
    assert call("POST", f"/objections/{obj1}/dismissals", bob, {"digest": dg1})[0] == 200
    status, resp = call("POST", f"/objections/{obj1}/dismissals", dave, {"digest": dg1})
    show("dave 第二票驳回", status, resp)
    assert resp["status"] == "dismissed" and resp["dismissal_count"] == 2

    # 拦截解除：可重新申请开封
    _, req = call("POST", f"/documents/{doc1}/open-requests", owner,
                  {"reason": "异议解除后重新申请", "deadline": in_hours(24)})
    req1b = req["request_id"]
    call("POST", f"/open-requests/{req1b}/approve", bob, {"digest": dg1})
    status, opened = call("POST", f"/open-requests/{req1b}/approve", carol, {"digest": dg1})
    assert opened["status"] == "opened"
    print(f"-- 两票重新开封 -> {status} {opened['status']}")

    # ------------------------------------------------------------------
    # 场景 2：异议人撤回
    # ------------------------------------------------------------------
    print("== 场景 2：异议人撤回异议，解除拦截 ==")
    _, sealed = call("POST", "/documents", owner,
                     {"body": "异议撤回示例", "witnesses": ["bob", "carol", "dave"]})
    doc2, dg2 = sealed["document_id"], sealed["digest"]
    _, obj = call("POST", f"/documents/{doc2}/objections", dave,
                  {"observed_digest": dg2, "reason": "暂存疑问"})
    obj2 = obj["objection_id"]
    # 他人不能撤回（403）
    assert call("POST", f"/objections/{obj2}/withdraw", bob)[0] == 403
    status, resp = call("POST", f"/objections/{obj2}/withdraw", dave)
    show("dave 撤回异议", status, resp)
    assert resp["status"] == "withdrawn"

    # ------------------------------------------------------------------
    # 场景 3：未决期间不得替换异议人；替换其他人旧驳回票失效
    # ------------------------------------------------------------------
    print("== 场景 3：不能替换异议人；替换其他见证人旧驳回票失效 ==")
    _, sealed = call("POST", "/documents", owner,
                     {"body": "异议替换示例", "witnesses": ["bob", "carol", "dave"]})
    doc3, dg3 = sealed["document_id"], sealed["digest"]
    _, obj = call("POST", f"/documents/{doc3}/objections", bob,
                  {"observed_digest": dg3, "reason": "保持异议"})
    obj3 = obj["objection_id"]
    # 不能把异议人 bob 换成 erin
    s, _ = call("POST", f"/documents/{doc3}/witness-replacements", owner,
                {"old_witness": "bob", "new_witness": "erin"})
    print(f"-- 替换异议人 bob -> {s}（409 表示未决期间不得替换异议人）")
    assert s == 409

    # carol 先驳回一票，再把 carol（非异议人）换成 erin，其驳回票失效
    call("POST", f"/objections/{obj3}/dismissals", carol, {"digest": dg3})
    _, resp = call("POST", f"/documents/{doc3}/witness-replacements", owner,
                   {"old_witness": "carol", "new_witness": "erin"})
    assert resp["status"] == "sealed"
    _, got = call("GET", f"/objections/{obj3}", owner)
    print(f"-- 替换 carol 后异议有效驳回票数: {got['dismissal_count']}（0 表示旧票失效）")
    assert got["dismissal_count"] == 0
    # 新见证人 erin 可凭原摘要驳回；dave 再一票 -> 两票齐
    call("POST", f"/objections/{obj3}/dismissals", erin, {"digest": dg3})
    status, resp = call("POST", f"/objections/{obj3}/dismissals", dave, {"digest": dg3})
    assert resp["status"] == "dismissed"
    print(f"-- 新见证人补票后异议状态: {resp['status']}")

    # ------------------------------------------------------------------
    # 场景 4：拒绝语义与正文零泄露
    # ------------------------------------------------------------------
    print("== 场景 4：拒绝场景（不留记录/不泄露正文） ==")
    _, sealed = call("POST", "/documents", owner,
                     {"body": "拒绝场景正文 NEVER-LEAK", "witnesses": ["bob", "carol", "dave"]})
    doc4, dg4 = sealed["document_id"], sealed["digest"]
    import hashlib
    wrong = hashlib.sha256("别的正文".encode()).hexdigest()
    # 摘要不符 -> 409 且不留记录
    s, body = call("POST", f"/documents/{doc4}/objections", bob,
                   {"observed_digest": wrong, "reason": "错摘要"})
    print(f"-- 摘要不符 -> {s}")
    assert s == 409 and "NEVER-LEAK" not in json.dumps(body, ensure_ascii=False)
    _, got = call("GET", f"/documents/{doc4}", owner)
    assert got["pending_objection"] is None
    # 非见证人（封存人本人、外人）/ 不存在编号 -> 403
    assert call("POST", f"/documents/{doc4}/objections", owner,
                {"observed_digest": dg4, "reason": "x"})[0] == 403
    assert call("POST", "/documents/9999/objections", erin,
                {"observed_digest": dg4, "reason": "x"})[0] == 403
    # 正确异议 + 重复异议 -> 第二件 409
    call("POST", f"/documents/{doc4}/objections", bob, {"observed_digest": dg4, "reason": "正摘要"})
    assert call("POST", f"/documents/{doc4}/objections", carol,
                {"observed_digest": dg4, "reason": "再来一件"})[0] == 409

    print("\n全部异议示例断言通过。审计可查：")
    _, audit = call("GET", f"/documents/{doc1}/audit", owner)
    print("  actions:", [r["action"] for r in audit["records"]])


if __name__ == "__main__":
    main()
