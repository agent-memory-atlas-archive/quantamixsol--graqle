"""SEC-01 finding 2: S3 push is a conditional write; concurrent writers cannot
silently overwrite each other."""

from __future__ import annotations

import hashlib
import threading

import pytest
from botocore.exceptions import ClientError

from graqle.core import kg_sync


class _StubS3:
    """In-memory S3 honouring IfMatch / IfNoneMatch on put_object."""

    def __init__(self):
        self.objects: dict[str, tuple[bytes, str]] = {}
        self.lock = threading.Lock()
        self.put_kwargs: list[dict] = []

    def head_object(self, Bucket, Key):  # noqa: N803
        if Key not in self.objects:
            raise ClientError({"Error": {"Code": "404"}}, "HeadObject")
        return {"ETag": self.objects[Key][1]}

    def put_object(self, Bucket, Key, Body, ContentType=None, IfMatch=None, IfNoneMatch=None):  # noqa: N803
        with self.lock:
            self.put_kwargs.append({"IfMatch": IfMatch, "IfNoneMatch": IfNoneMatch})
            current = self.objects.get(Key)
            if IfNoneMatch == "*" and current is not None:
                raise ClientError({"Error": {"Code": "PreconditionFailed"}}, "PutObject")
            if IfMatch is not None and (current is None or current[1] != IfMatch):
                raise ClientError({"Error": {"Code": "PreconditionFailed"}}, "PutObject")
            etag = '"' + hashlib.md5(Body).hexdigest() + '"'
            self.objects[Key] = (Body, etag)
            return {"ETag": etag}


KEY = "graphs/h/proj/graqle.json"


def test_create_uses_if_none_match_and_second_creator_conflicts():
    s3 = _StubS3()
    kg_sync.conditional_put(s3, KEY, b"A", None)
    assert s3.put_kwargs[0] == {"IfMatch": None, "IfNoneMatch": "*"}
    with pytest.raises(kg_sync.KGPushConflictError):
        kg_sync.conditional_put(s3, KEY, b"B", None)
    assert s3.objects[KEY][0] == b"A"


def test_concurrent_writers_exactly_one_wins_no_lost_update():
    s3 = _StubS3()
    base = kg_sync.conditional_put(s3, KEY, b"base", None)
    results: list[str] = []
    barrier = threading.Barrier(2)

    def writer(payload: bytes):
        barrier.wait()
        try:
            kg_sync.conditional_put(s3, KEY, payload, base)  # both read the same baseline
            results.append("ok")
        except kg_sync.KGPushConflictError:
            results.append("conflict")

    threads = [threading.Thread(target=writer, args=(p,)) for p in (b"W1", b"W2")]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sorted(results) == ["conflict", "ok"]
    assert s3.objects[KEY][0] in (b"W1", b"W2")


def test_other_s3_errors_are_not_reported_as_conflict():
    class _Boom(_StubS3):
        def put_object(self, **kw):
            raise ClientError({"Error": {"Code": "AccessDenied"}}, "PutObject")

    with pytest.raises(ClientError):
        kg_sync.conditional_put(_Boom(), KEY, b"x", "etag")


def test_push_worker_sends_precondition_and_conflict_is_final(tmp_path, monkeypatch, caplog):
    s3 = _StubS3()
    s3.objects[KEY] = (b"theirs", '"theirs"')
    graph = tmp_path / "graqle.json"
    graph.write_text('{"nodes": []}')
    creds = type("C", (), {"email": "a@b.c", "is_authenticated": True})()
    monkeypatch.setattr(kg_sync, "_load_creds", lambda: creds)
    monkeypatch.setattr(kg_sync, "_s3_key", lambda h, p, f="graqle.json": KEY)
    monkeypatch.setattr(kg_sync, "_known_etags", {})
    import boto3
    monkeypatch.setattr(boto3, "client", lambda *a, **k: s3)

    kg_sync._push_worker(graph, "proj", retry_on_error=True)

    assert s3.objects[KEY][0] == b"theirs"  # no overwrite
    assert len(s3.put_kwargs) == 1  # conflict is not retried
    assert any("CONFLICT" in r.message for r in caplog.records)


def test_push_worker_succeeds_with_matching_baseline(tmp_path, monkeypatch):
    s3 = _StubS3()
    s3.objects[KEY] = (b"base", '"base"')
    graph = tmp_path / "graqle.json"
    graph.write_text('{"nodes": []}')
    creds = type("C", (), {"email": "a@b.c", "is_authenticated": True})()
    monkeypatch.setattr(kg_sync, "_load_creds", lambda: creds)
    monkeypatch.setattr(kg_sync, "_s3_key", lambda h, p, f="graqle.json": KEY)
    monkeypatch.setattr(kg_sync, "_known_etags", {KEY: '"base"'})
    import boto3
    monkeypatch.setattr(boto3, "client", lambda *a, **k: s3)

    kg_sync._push_worker(graph, "proj", retry_on_error=False)

    assert s3.objects[KEY][0] == b'{"nodes": []}'
    assert s3.put_kwargs[0]["IfMatch"] == '"base"'


def test_check_push_conflict_detects_etag_mismatch(tmp_path, monkeypatch):
    s3 = _StubS3()
    s3.objects[KEY] = (b"x", '"new"')
    graph = tmp_path / "graqle.json"
    graph.write_text("{}")
    monkeypatch.setattr(kg_sync, "_s3_key", lambda h, p, f="graqle.json": KEY)
    monkeypatch.setattr(kg_sync, "_known_etags", {KEY: '"old"'})

    class _Head(_StubS3):
        def head_object(self, Bucket, Key):  # noqa: N803
            import datetime
            return {"ETag": '"new"', "LastModified": datetime.datetime(2000, 1, 1)}

    import boto3
    monkeypatch.setattr(boto3, "client", lambda *a, **k: _Head())
    conflict, reason = kg_sync.check_push_conflict(graph, "proj", "h")
    assert conflict and "ETag" in reason
