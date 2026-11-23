import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))

from gtare import canon, exporter, importer, model, safety, store  # noqa: E402

SHA = "ab" * 32
BID = "b-" + SHA[:16]
BUILD = {"schema": 1, "build_id": BID, "sha256": SHA, "image_base": "0x140000000", "file_size": 123}

SNAP = {
    "program": {"sha256": SHA, "image_base": "0x140000000"},
    "functions": [
        {"rva": 0x1000, "name": "Player_Update", "namespace": "Game::Player", "name_source": "USER_DEFINED",
         "sig_source": "USER_DEFINED", "comment": "Per-frame update.", "size": 64,
         "prototype": {"return_type": "void", "calling_convention": "__fastcall",
                       "params": [{"name": "self", "type": "Player *"}]}},
        {"rva": 0x2000, "name": "FUN_00002000", "namespace": "", "name_source": "DEFAULT", "sig_source": "DEFAULT"},
        {"rva": 0x3000, "name": "auto_thing", "namespace": "", "name_source": "ANALYSIS", "sig_source": "DEFAULT"},
    ],
    "globals": [{"rva": 0x9000, "name": "g_World", "namespace": "", "name_source": "USER_DEFINED",
                 "type": "World *", "size": 8}],
    "types": [{"kind": "struct", "name": "Player", "namespace": "Game", "size": 16,
               "members": [{"offset": 8, "name": "hp", "type": "float", "size": 4},
                           {"offset": 0, "name": "id", "type": "int", "size": 4}]},
              {"kind": "enum", "name": "Mode", "namespace": "", "size": 4,
               "values": [{"name": "B", "value": 1}, {"name": "A", "value": 0}]},
              {"kind": "struct", "name": "Bad<T>", "namespace": "", "size": 1}],
}


def make_repo():
    d = tempfile.mkdtemp()
    store.write_json(os.path.join(store.build_dir(d, BID), "build.json"), BUILD)
    return d


class CoreTests(unittest.TestCase):
    def test_export_is_minimal_deterministic_and_valid(self):
        repo = make_repo()
        recs, skipped = exporter.snapshot_to_records(SNAP, "alice", "low")
        self.assertEqual(len(recs), 4)  # default-named + auto function excluded; Bad<T> skipped
        self.assertEqual(len(skipped), 1)
        plan = exporter.plan_changes(repo, BID, recs, "alice")
        self.assertEqual(len(plan.new), 4)
        exporter.write_plan(repo, BID, plan)
        errors, _ = store.check_database(repo)
        self.assertEqual(errors, [])
        # Re-export identical findings: no changes.
        plan2 = exporter.plan_changes(repo, BID, recs, "alice")
        self.assertEqual((len(plan2.new), len(plan2.modified), len(plan2.unchanged)), (0, 0, 4))
        # Members/values are sorted canonically.
        rec = json.load(open(store.record_path(repo, BID, [r for r in recs if r["name"] == "Player"][0])))
        self.assertEqual([m["offset"] for m in rec["members"]], [0, 8])

    def test_stale_and_modified_detection(self):
        repo = make_repo()
        recs, _ = exporter.snapshot_to_records(SNAP, "alice", "low")
        exporter.write_plan(repo, BID, exporter.plan_changes(repo, BID, recs, "alice"))
        changed = json.loads(json.dumps(SNAP))
        changed["functions"][0]["name"] = "Player_Tick"
        new_recs, _ = exporter.snapshot_to_records(changed, "bob", "low")
        # Bob never pulled alice's record -> must not silently overwrite it.
        plan = exporter.plan_changes(repo, BID, new_recs, "bob")
        self.assertEqual(len(plan.stale), 1)
        self.assertEqual(len(plan.modified), 0)
        # After "pulling" (state records the hash), the edit is a legitimate modification.
        old = json.load(open(store.record_path(repo, BID, [r for r in recs if r["kind"] == "function"][0])))
        st = importer.load_state(repo, BID)
        st["records"]["fn:0x00001000"] = {"hash": canon.content_hash(old)}
        importer.save_state(repo, BID, st)
        plan = exporter.plan_changes(repo, BID, new_recs, "bob")
        self.assertEqual(len(plan.modified), 1)
        self.assertEqual(plan.modified[0]["contributor"], "alice")
        self.assertEqual(plan.modified[0]["updated_by"], "bob")

    def test_incremental_bundle(self):
        repo = make_repo()
        recs, _ = exporter.snapshot_to_records(SNAP, "alice", "low")
        exporter.write_plan(repo, BID, exporter.plan_changes(repo, BID, recs, "alice"))
        b1 = importer.build_bundle(repo, BUILD)
        self.assertEqual((len(b1["functions"]), len(b1["globals"]), len(b1["types"])), (1, 1, 2))
        importer.apply_report(repo, BID, b1, {"applied": [{"id": r["id"], "name": "x", "sig": "y"}
                                                           for g in ("functions", "globals", "types") for r in b1[g]]})
        b2 = importer.build_bundle(repo, BUILD)
        self.assertEqual(sum(len(b2[g]) for g in ("functions", "globals", "types")), 0)
        self.assertEqual(len(importer.build_bundle(repo, BUILD, full=True)["functions"]), 1)

    def test_validation_catches_problems(self):
        good = canon.prune({"schema": 1, "kind": "function", "id": "fn:0x00001000", "rva": "0x00001000", "name": "F",
                            "status": "manual", "confidence": "low", "contributor": "alice"})
        self.assertEqual(model.validate_record(good), [])
        for patch in ({"rva": "0x1000"}, {"status": "reviewed"}, {"id": "fn:0x00002000"}, {"bogus": 1},
                      {"comment": "mov eax, 1\nmov ebx, 2\ncall eax"},
                      {"comment": "int iVar1;\niVar1 = 3;"}, {"comment": "41 42 43 44 45 46 47 48 49"}):
            self.assertTrue(model.validate_record(dict(good, **patch)), patch)

    def test_duplicates_and_bad_paths(self):
        repo = make_repo()
        recs, _ = exporter.snapshot_to_records(SNAP, "alice", "low")
        exporter.write_plan(repo, BID, exporter.plan_changes(repo, BID, recs, "alice"))
        dup = dict([r for r in recs if r["kind"] == "function"][0], rva="0x00005000", id="fn:0x00005000")
        store.write_json(store.record_path(repo, BID, dup), dup)
        misplaced = dict(dup, rva="0x00006000", id="fn:0x00006000", name="Other")
        store.write_json(os.path.join(store.build_dir(repo, BID), "functions", "9999", "x.json"), misplaced)
        errors, _ = store.check_database(repo)
        text = " | ".join(m for _, m in errors)
        self.assertIn("duplicate definition", text)
        self.assertIn("record belongs at", text)

    def test_safety_rejects_binaries(self):
        repo = make_repo()
        os.makedirs(os.path.join(repo, "db", "builds", BID, "functions", "0000"))
        files = {
            "game.exe": b"MZ\x90\x00",
            "db/builds/%s/functions/0000/blob.json" % BID: b"MZ\x90\x00\x03\x00",
            "docs/dump.txt": b"abc\x00\x01\x02def",
            "db/notes.md": b"# fine",
            "tools/x.dmp": b"hello",
            "gtare.local.json": b"{}",
        }
        for rel, data in files.items():
            p = os.path.join(repo, *rel.split("/"))
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "wb").write(data)
        for rel in files:
            self.assertTrue(safety.scan_file(repo, rel), rel)
        open(os.path.join(repo, "docs", "ok.md"), "w").write("# hello\n")
        self.assertEqual(safety.scan_file(repo, "docs/ok.md"), [])


if __name__ == "__main__":
    unittest.main()
