"""
In-memory database — pure Python implementation.
Replaces mongomock-motor to avoid RecursionError bugs.
Supports: insert_many, find, count_documents, aggregate ($group/$sort/$match), find_one_and_update
"""
import copy
from datetime import datetime, timezone, timedelta
from collections import defaultdict


class InMemoryCollection:
    def __init__(self):
        self._docs = []

    # ── Writes ──────────────────────────────────────────────────────────────

    async def insert_many(self, docs):
        for d in docs:
            self._docs.append(copy.deepcopy(d))

        class _Result:
            inserted_ids = [i for i in range(len(docs))]
        return _Result()

    async def find_one_and_update(self, filter_q, update, return_document=True):
        for i, doc in enumerate(self._docs):
            if _matches(doc, filter_q):
                if "$set" in update:
                    self._docs[i].update(update["$set"])
                return copy.deepcopy(self._docs[i])
        return None

    # ── Reads ────────────────────────────────────────────────────────────────

    def find(self, filter_q=None, projection=None):
        return _Cursor(self._docs, filter_q or {}, projection)

    async def count_documents(self, filter_q=None):
        return sum(1 for d in self._docs if _matches(d, filter_q or {}))

    def aggregate(self, pipeline):
        return _AggCursor(self._docs, pipeline)


class _Cursor:
    def __init__(self, docs, filter_q, projection):
        self._docs = docs
        self._filter = filter_q
        self._projection = projection
        self._sort_key = None
        self._sort_dir = 1
        self._limit_n = None

    def sort(self, key, direction=-1):
        self._sort_key = key
        self._sort_dir = direction
        return self

    def limit(self, n):
        self._limit_n = n
        return self

    async def to_list(self, length=None):
        results = [copy.deepcopy(d) for d in self._docs if _matches(d, self._filter)]
        if self._sort_key:
            results.sort(key=lambda d: d.get(self._sort_key, ""), reverse=(self._sort_dir == -1))
        cap = length or self._limit_n
        if cap:
            results = results[:cap]
        return results


class _AggCursor:
    def __init__(self, docs, pipeline):
        self._results = self._run(docs, pipeline)
        self._idx = 0

    def _run(self, docs, pipeline):
        data = [copy.deepcopy(d) for d in docs]
        for stage in pipeline:
            if "$match" in stage:
                data = [d for d in data if _matches(d, stage["$match"])]
            elif "$group" in stage:
                data = _group(data, stage["$group"])
            elif "$sort" in stage:
                sk = list(stage["$sort"].keys())[0]
                rev = stage["$sort"][sk] == -1
                data.sort(key=lambda d: d.get(sk, 0), reverse=rev)
        return data

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self._idx >= len(self._results):
            raise StopAsyncIteration
        doc = self._results[self._idx]
        self._idx += 1
        return doc


# ── Helpers ──────────────────────────────────────────────────────────────────

def _matches(doc, filter_q):
    for key, val in filter_q.items():
        dv = doc.get(key)
        if isinstance(val, dict):
            for op, operand in val.items():
                if op == "$gte" and not (dv is not None and dv >= operand):
                    return False
                elif op == "$lt" and not (dv is not None and dv < operand):
                    return False
                elif op == "$lte" and not (dv is not None and dv <= operand):
                    return False
                elif op == "$gt" and not (dv is not None and dv > operand):
                    return False
                elif op == "$ne" and dv == operand:
                    return False
        else:
            if dv != val:
                return False
    return True


def _group(data, group_spec):
    id_field = group_spec["_id"]   # e.g. "$threat_type"
    field_name = id_field.lstrip("$") if isinstance(id_field, str) else None

    buckets = defaultdict(lambda: {"_id": None, **{k: 0 for k in group_spec if k != "_id"}})

    for doc in data:
        key = doc.get(field_name) if field_name else None
        bucket = buckets[key]
        bucket["_id"] = key
        for out_field, expr in group_spec.items():
            if out_field == "_id":
                continue
            if isinstance(expr, dict):
                op = list(expr.keys())[0]
                src = list(expr.values())[0]
                src_field = src.lstrip("$") if isinstance(src, str) else None
                val = doc.get(src_field, 0) if src_field else 1
                if op == "$sum":
                    bucket[out_field] = bucket.get(out_field, 0) + (val if src_field else 1)
                elif op == "$avg":
                    bucket.setdefault("__count__" + out_field, 0)
                    bucket.setdefault("__sum__" + out_field, 0)
                    bucket["__count__" + out_field] += 1
                    bucket["__sum__" + out_field] += (val or 0)
                    bucket[out_field] = bucket["__sum__" + out_field] / bucket["__count__" + out_field]
                elif op == "$max":
                    bucket[out_field] = max(bucket.get(out_field, float("-inf")), val or 0)
                elif op == "$min":
                    bucket[out_field] = min(bucket.get(out_field, float("inf")), val or 0)

    return list(buckets.values())


# ── DB Singleton ─────────────────────────────────────────────────────────────

class InMemoryDB:
    def __init__(self):
        self.network_logs = InMemoryCollection()
        self.alerts = InMemoryCollection()


from typing import Optional

_db: Optional[InMemoryDB] = None


async def connect_db():
    global _db
    _db = InMemoryDB()
    print("Connected to pure in-memory DB (no mongomock)")


async def close_db():
    global _db
    _db = None


def get_db() -> InMemoryDB:
    return _db
