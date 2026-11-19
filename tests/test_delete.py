"""Delete outcome (I5): task polling, accepted-not-verified, and the shared delete loop (I7)."""
import pytest

from helpers import S, Resp, make_client

TASK = "https://vcd.example/api/task/11111111-2222-3333-4444-555555555555"


def shadow(vsc, n="s1"):
    return vsc.ShadowVM(n, S + n, "tpl", "", "ds1", n, "")


def test_202_with_location_polls_task_until_success(vsc, sleeps):
    c = make_client(vsc, {
        "DELETE": lambda call: Resp(202, None, headers={"Location": TASK}),
        "GET /api/task/11111111-2222-3333-4444-555555555555": [
            Resp(200, {"status": "running"}), Resp(200, {"status": "running"}), Resp(200, {"status": "success"})],
    })
    r = c.delete_shadow_vm(shadow(vsc))
    assert r.status == "deleted" and r.ok
    assert r.task_href == TASK and r.task_status == "success"
    assert [call.method for call in c.session.calls] == ["DELETE", "GET", "GET", "GET"]


def test_task_error_reports_failure_with_message(vsc, sleeps):
    c = make_client(vsc, {
        "DELETE": lambda call: Resp(202, None, headers={"Location": TASK}),
        "GET /api/task/11111111-2222-3333-4444-555555555555":
            lambda call: Resp(200, {"status": "error", "error": {"message": "VM is in use"}}),
    })
    r = c.delete_shadow_vm(shadow(vsc))
    assert r.status == "failed" and not r.ok
    assert "VM is in use" in r.message


@pytest.mark.parametrize("state", ["aborted", "canceled"])
def test_task_aborted_or_canceled_is_failure(vsc, sleeps, state):
    c = make_client(vsc, {
        "DELETE": lambda call: Resp(202, None, headers={"Location": TASK}),
        "GET /api/task/11111111-2222-3333-4444-555555555555": lambda call: Resp(200, {"status": state}),
    })
    assert c.delete_shadow_vm(shadow(vsc)).status == "failed"


def test_task_href_in_json_body(vsc, sleeps):
    c = make_client(vsc, {
        "DELETE": lambda call: Resp(200, {"href": TASK, "type": "application/vnd.vmware.vcloud.task+json",
                                          "status": "queued"}),
        "GET /api/task/11111111-2222-3333-4444-555555555555": lambda call: Resp(200, {"status": "success"}),
    })
    assert c.delete_shadow_vm(shadow(vsc)).status == "deleted"


def test_202_without_task_is_accepted_not_verified(vsc):
    c = make_client(vsc, {"DELETE": lambda call: Resp(202)})
    r = c.delete_shadow_vm(shadow(vsc))
    assert r.status == "accepted_unverified"
    assert "not verified" in r.message


def test_204_is_deleted(vsc):
    c = make_client(vsc, {"DELETE": lambda call: Resp(204)})
    assert c.delete_shadow_vm(shadow(vsc)).status == "deleted"


def test_task_timeout(vsc, sleeps, monkeypatch):
    clock = iter(range(0, 100000, 100))
    monkeypatch.setattr(vsc, "_monotonic", lambda: next(clock))
    c = make_client(vsc, {
        "DELETE": lambda call: Resp(202, None, headers={"Location": TASK}),
        "GET /api/task/11111111-2222-3333-4444-555555555555": lambda call: Resp(200, {"status": "running"}),
    })
    r = c.delete_shadow_vm(shadow(vsc))
    assert r.status == "timeout" and not r.ok


def test_failed_delete_reports_http_status(vsc):
    c = make_client(vsc, {"DELETE": lambda call: Resp(400, {"message": "bad"})})
    r = c.delete_shadow_vm(shadow(vsc))
    assert r.status == "failed" and r.http_status == 400


def test_shared_loop_stops_after_three_failures_and_pauses(vsc, sleeps):
    c = make_client(vsc, {"DELETE": lambda call: Resp(500)})
    items = [shadow(vsc, f"s{i}") for i in range(5)]
    run = vsc.delete_shadow_vms(c, items)
    assert [r.status for r in run.results] == ["failed"] * 3 + ["skipped"] * 2
    assert "3 consecutive" in run.stopped_reason
    assert sleeps.count(3) == 2


def test_shared_loop_success_resets_failure_count(vsc, sleeps):
    seq = [Resp(500), Resp(500), Resp(204), Resp(500), Resp(500), Resp(204)]
    c = make_client(vsc, {"DELETE": seq})
    run = vsc.delete_shadow_vms(c, [shadow(vsc, f"s{i}") for i in range(6)])
    assert run.stopped_reason == ""
    assert run.deleted == 2 and run.failed == 4


def test_shared_loop_stops_on_403(vsc, sleeps):
    c = make_client(vsc, {"DELETE": lambda call: Resp(403)})
    run = vsc.delete_shadow_vms(c, [shadow(vsc, f"s{i}") for i in range(3)])
    assert [r.status for r in run.results] == ["failed", "skipped", "skipped"]
