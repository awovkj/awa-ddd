"""Real loopback integration, including vulnerable/fixed authorization controls."""
import base64
import concurrent.futures
from datetime import datetime, timedelta, timezone
import http.server
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from awa_ddd import engine
from awa_ddd.assessment import evaluate,record_finding
from awa_ddd.scenario import run_scenario
from awa_ddd.store import Project,EngineError
from awa_ddd.scope import require_scope,normalize_url
from awa_ddd.__main__ import dispatch


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self,*args):
        pass

    def do_GET(self):
        self.server.calls+=1
        actor="alice" if "actor=alice" in self.headers.get("Cookie","") else "bob" if "actor=bob" in self.headers.get("Cookie","") else self.headers.get("X-Actor")
        status=200
        if self.path=="/whoami":
            status=200 if actor else 401
            body={"id":actor,"roles":["user"],"tenant":"tenant-one"}
        elif self.path.startswith("/items/"):
            status=200 if actor=="alice" or (actor and self.server.vulnerable) else 403
            if "mode=deny" in self.path:
                status=403
            body={"id":"owned-1","secret":"synthetic-protected-value"} if status==200 else {"error":"denied"}
        elif self.path.startswith("/search"):
            body={"items":["different"] if "q=control" in self.path else ["same"],"requestId":str(self.server.calls)}
        elif self.path=="/redirect":
            self.send_response(302)
            self.send_header("Location","http://127.0.0.1:1/outside")
            self.send_header("Content-Length","0")
            self.end_headers()
            return
        else:
            body={"ok":True}
        raw=json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        self.server.calls+=1
        payload=json.loads(self.rfile.read(int(self.headers.get("Content-Length","0"))))
        if payload.get("action")=="mutate":
            self.server.state="approved"
        raw=json.dumps({"state":self.server.state}).encode()
        self.send_response(self.server.write_status)
        self.send_header("Content-Length",str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix="awa-test-")
        self.addCleanup(self.tmp.cleanup)
        self.server=http.server.ThreadingHTTPServer(("127.0.0.1",0),Handler)
        self.server.calls=0
        self.server.vulnerable=True
        threading.Thread(target=self.server.serve_forever,daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.base=f"http://127.0.0.1:{self.server.server_port}"
        engine.create_project(self.tmp.name,{"project_id":"test","target":self.base})
        self.project=Project(self.tmp.name,"test")
        self.addCleanup(self.project.close)
        self.identity=engine.register_operation(self.project,{"url":self.base+"/whoami","method":"GET","auth":"authenticated"})

    def actors(self):
        sessions={}
        for name in ("alice","bob"):
            engine.add_actor(self.project,{"actor_id":name,"subject":name,"roles":["user"],"tenant_id":"tenant-one"})
            session=engine.add_session(self.project,{"actor_id":name,"headers":{"Cookie":"actor="+name}})
            engine.verify_identity(self.project,{"operation_id":self.identity["id"],"session_id":session["id"],
                "subject_selector":"/id","roles_selector":"/roles","tenant_selector":"/tenant"})
            sessions[name]=session["id"]
        return sessions

    def owned(self):
        sessions=self.actors()
        operation=engine.register_operation(self.project,{"url":self.base+"/items/{id}","method":"GET","auth":"authenticated","ownership":True})
        resource=engine.add_resource(self.project,{"operation_id":operation["id"],"owner_actor_id":"alice","external_id":"owned-1",
            "request_binding":{"location":"path","selector":"id"}})
        engine.build_plan(self.project)
        obligation=next(x for x in self.project.list("obligation") if x["kind"]=="ownership")
        def capture(name):
            return engine.capture(self.project,{"operation_id":operation["id"],"url":self.base+"/items/owned-1",
                "session_id":sessions[name],"resource_id":resource["id"]})
        return operation,resource,obligation,capture,sessions

    def test_same_role_sessions_are_distinct_and_verified(self):
        sessions=self.actors()
        self.assertNotEqual(sessions["alice"],sessions["bob"])
        self.assertEqual(2,len(self.project.list("session")))
        self.assertEqual("alice",engine.session_valid(self.project,self.project.get("session",sessions["alice"]))["id"])
        self.assertNotIn("headers",engine.public_session(self.project.get("session",sessions["alice"])))

    def test_identity_mismatch_cannot_be_self_certified(self):
        engine.add_actor(self.project,{"actor_id":"alice","subject":"alice"})
        session=engine.add_session(self.project,{"actor_id":"alice","headers":{"Cookie":"actor=bob"}})
        with self.assertRaisesRegex(EngineError,"different actor"):
            engine.verify_identity(self.project,{"operation_id":self.identity["id"],"session_id":session["id"],"subject_selector":"/id"})
        self.assertIsNone(self.project.get("session",session["id"])["verified_at"])

    def test_expired_or_rotated_session_reopens_coverage(self):
        op,res,ob,capture,sessions=self.owned()
        a,b=capture("alice"),capture("bob")
        decision=evaluate(self.project,{"obligation_id":ob["id"],"evidence_ids":[a["id"],b["id"]],"oracle":{"type":"authorization","selector":"/secret"}})
        self.assertEqual("confirmed",decision["outcome"])
        engine.add_session(self.project,{"actor_id":"bob","session_id":sessions["bob"],"headers":{"Cookie":"actor=bob"}})
        gap=next(x for x in engine.evaluate_coverage(self.project)["gaps"] if x["id"]==ob["id"])
        self.assertEqual("repair_evidence",gap["next_action"])

    def test_vulnerable_and_fixed_authorization_controls(self):
        op,res,ob,capture,sessions=self.owned()
        for vulnerable,expected in [(True,"confirmed"),(False,"refuted")]:
            self.server.vulnerable=vulnerable
            a,b=capture("alice"),capture("bob")
            result=evaluate(self.project,{"obligation_id":ob["id"],"evidence_ids":[a["id"],b["id"]],"oracle":{"type":"authorization","selector":"/secret"}})
            self.assertEqual(expected,result["outcome"])

    def test_same_actor_and_wrong_resource_are_rejected(self):
        op,res,ob,capture,sessions=self.owned()
        a,b=capture("alice"),capture("alice")
        with self.assertRaisesRegex(EngineError,"different actual actors"):
            evaluate(self.project,{"obligation_id":ob["id"],"evidence_ids":[a["id"],b["id"]],"oracle":{"type":"authorization","selector":"/secret"}})
        calls=self.server.calls
        with self.assertRaises(EngineError):
            engine.capture(self.project,{"operation_id":op["id"],"url":self.base+"/items/not-owned","resource_id":res["id"],"session_id":sessions["bob"]})
        self.assertEqual(calls,self.server.calls)

    def test_authorization_refutation_rejects_changed_business_request(self):
        op,res,ob,capture,sessions=self.owned()
        allowed=capture("alice")
        denied=engine.capture(self.project,{"operation_id":op["id"],"url":self.base+"/items/owned-1?mode=deny",
            "session_id":sessions["bob"],"resource_id":res["id"]})
        self.assertEqual(403,denied["status_code"])
        with self.assertRaisesRegex(EngineError,"same request"):
            evaluate(self.project,{"obligation_id":ob["id"],"evidence_ids":[allowed["id"],denied["id"]],
                "oracle":{"type":"authorization","selector":"/secret"}})
        actual=capture("bob")
        self.assertEqual("confirmed",evaluate(self.project,{"obligation_id":ob["id"],"evidence_ids":[allowed["id"],actual["id"]],
            "oracle":{"type":"authorization","selector":"/secret"}})["outcome"])

    def test_tampered_evidence_reopens_shared_plan(self):
        op,res,ob,capture,sessions=self.owned()
        a,b=capture("alice"),capture("bob")
        decision=evaluate(self.project,{"obligation_id":ob["id"],"evidence_ids":[a["id"],b["id"]],"oracle":{"type":"authorization","selector":"/secret"}})
        record_finding(self.project,{"decision_id":decision["id"],"title":"test ownership","category":"idor","impact":"synthetic protected value","remediation":"check ownership"})
        (self.project.base/b["artifact_path"]).write_text("{}",encoding="utf-8")
        coverage=engine.evaluate_coverage(self.project)
        self.assertTrue(any(x["id"]==ob["id"] and x["next_action"]=="repair_evidence" for x in coverage["gaps"]))
        self.assertFalse(coverage["findings"][0]["current"])

    def test_unknown_inputs_and_missing_roles_remain_open(self):
        self.actors()
        op=engine.register_operation(self.project,{"url":self.base+"/admin","method":"GET","auth":"restricted","allowed_roles":["admin"],
            "inputs":[{"name":"extra","location":"query","selector":"extra","consumer":"unknown"}]})
        result=engine.build_plan(self.project)
        gaps=[g for g in result["gaps"] if g["operation_id"]==op["id"]]
        self.assertEqual({None,"alice","bob"},{g.get("actor_id") for g in gaps if g["kind"]=="access"})
        self.assertTrue(any(g["kind"]=="input_review" for g in gaps))

    def test_request_id_noise_is_not_business_sensitivity(self):
        op=engine.register_operation(self.project,{"url":self.base+"/search","method":"GET","auth":"public",
            "inputs":[{"name":"q","location":"query","selector":"q","consumer":"query"}]})
        engine.build_plan(self.project)
        ob=next(x for x in self.project.list("obligation") if x["kind"]=="input_test")
        evidence=[engine.capture(self.project,{"operation_id":op["id"],"url":self.base+"/search?q="+v})["id"] for v in ["a","variant","a"]]
        args={"obligation_id":ob["id"],"evidence_ids":evidence,"oracle":{"type":"semantic_negative","selector":"/items","baseline_expected":["same"],"control_expected":["different"]}}
        with self.assertRaisesRegex(EngineError,"controls"):
            evaluate(self.project,args)
        args["evidence_ids"][2]=engine.capture(self.project,{"operation_id":op["id"],"url":self.base+"/search?q=control"})["id"]
        self.assertEqual("refuted",evaluate(self.project,args)["outcome"])

    def test_runtime_label_cannot_replace_an_observer(self):
        op=engine.register_operation(self.project,{"url":self.base+"/","method":"GET","auth":"public"})
        engine.build_plan(self.project)
        ob=next(x for x in self.project.list("obligation") if x["kind"]=="baseline")
        evidence=engine.capture(self.project,{"operation_id":op["id"]})
        with self.assertRaisesRegex(EngineError,"runtime labels"):
            evaluate(self.project,{"obligation_id":ob["id"],"evidence_ids":[evidence["id"]],"oracle":{"type":"runtime_observation"}})

    def test_scenario_failure_keeps_capture_and_blocks_blind_retry(self):
        op=engine.register_operation(self.project,{"url":self.base+"/","method":"GET","auth":"public"})
        args={"idempotency_key":"failed-experiment","scenario":{"steps":[{"id":"normal","operation_id":op["id"],"extract":{"ok":"/ok"}},
            {"id":"invalid","operation_id":op["id"],"assertions":[{"selector":"/ok","equals":False}]}]}}
        with self.assertRaises(EngineError):
            run_scenario(self.project,args)
        run=next(x for x in self.project.list("run") if x["kind"]=="scenario")
        self.assertEqual("failed",run["status"])
        self.assertEqual(2,len(run["evidence_ids"]))
        calls=self.server.calls
        with self.assertRaisesRegex(EngineError,"never blindly replayed"):
            run_scenario(self.project,args)
        self.assertEqual(calls,self.server.calls)

    def test_http_idempotency_never_replays_completed_request(self):
        op=engine.register_operation(self.project,{"url":self.base+"/","method":"GET"})
        first=engine.capture(self.project,{"operation_id":op["id"],"idempotency_key":"one"})
        calls=self.server.calls
        second=engine.capture(self.project,{"operation_id":op["id"],"idempotency_key":"one"})
        self.assertEqual(first["id"],second["id"])
        self.assertEqual(calls,self.server.calls)

    def test_redirects_and_framing_overrides_do_not_escape(self):
        op=engine.register_operation(self.project,{"url":self.base+"/redirect","method":"GET"})
        evidence=engine.capture(self.project,{"operation_id":op["id"]})
        self.assertEqual(302,evidence["status_code"])
        self.assertFalse(self.project.read_artifact(evidence)["redirect_followed"])
        with self.assertRaises(EngineError):
            engine.capture(self.project,{"operation_id":op["id"],"url":"http://127.0.0.1:1/redirect"})
        with self.assertRaises(EngineError):
            engine.capture(self.project,{"operation_id":op["id"],"headers":{"Cookie":"actor=alice"}})

    def test_distinct_graphql_operations_and_media_types(self):
        ids=[]
        for name in ["ReadOne","UpdateOne"]:
            ids.append(engine.register_operation(self.project,{"url":self.base+"/graphql","method":"POST","protocol":"graphql","operation_name":name,"content_type":"application/json"})["id"])
        self.assertNotEqual(*ids)

    def test_scope_blocks_normalization_and_project_path_escapes(self):
        for value in [self.base+"/x/../admin",self.base+"/%252e%252e/admin",self.base+"/x\\admin"]:
            with self.assertRaises(EngineError):
                normalize_url(value)
        with self.assertRaises(EngineError):
            Project(self.tmp.name,"../escape",create=True)

    def test_only_one_concurrent_run_claim_succeeds(self):
        def claim(_):
            with Project(self.tmp.name,"test") as project:
                try:
                    project.claim({"id":"same-id","status":"running"})
                    return True
                except EngineError:
                    return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            self.assertEqual(1,sum(pool.map(claim,range(4))))

    def test_json_cli_protocol_and_error_exit(self):
        command=[sys.executable,"-X","utf8","-B","-m","awa_ddd","--workspace",self.tmp.name]
        success=subprocess.run(command,input=json.dumps({"action":"project.status","args":{"project_id":"test"}}),text=True,encoding="utf-8",capture_output=True,cwd=ROOT)
        self.assertEqual(0,success.returncode,success.stderr+success.stdout)
        self.assertTrue(json.loads(success.stdout)["ok"])
        failure=subprocess.run(command,input=json.dumps({"action":"unknown","args":{"project_id":"test"}}),text=True,encoding="utf-8",capture_output=True,cwd=ROOT)
        self.assertEqual(2,failure.returncode)
        self.assertFalse(json.loads(failure.stdout)["ok"])

    def test_transactions_rollback_nested_entities_and_events(self):
        with self.assertRaisesRegex(RuntimeError,"rollback"):
            with self.project.transaction():
                self.project.put("candidate",{"id":"outer"})
                with self.project.transaction():
                    self.project.put("candidate",{"id":"inner"})
                    self.project.event("rollback.probe",{})
                raise RuntimeError("rollback")
        self.assertIsNone(self.project.get("candidate","outer",required=False))
        self.assertIsNone(self.project.get("candidate","inner",required=False))
        self.assertEqual(0,self.project.connection.execute("SELECT COUNT(*) FROM events WHERE type='rollback.probe'").fetchone()[0])

    def test_idempotency_key_cannot_rebind_rotated_session(self):
        sessions=self.actors()
        op=engine.register_operation(self.project,{"url":self.base+"/","method":"GET","auth":"authenticated"})
        args={"operation_id":op["id"],"session_id":sessions["alice"],"idempotency_key":"rotated"}
        engine.capture(self.project,args)
        engine.add_session(self.project,{"actor_id":"alice","session_id":sessions["alice"],"headers":{"Cookie":"actor=alice"}})
        engine.verify_identity(self.project,{"operation_id":self.identity["id"],"session_id":sessions["alice"],
            "subject_selector":"/id","roles_selector":"/roles","tenant_selector":"/tenant"})
        calls=self.server.calls
        with self.assertRaisesRegex(EngineError,"another request"):
            engine.capture(self.project,args)
        self.assertEqual(calls,self.server.calls)

    def test_custom_identity_header_cannot_be_overridden(self):
        sessions=self.actors()
        engine.add_session(self.project,{"actor_id":"bob","session_id":sessions["bob"],"headers":{"X-Actor":"bob"},
                                         "credential_header_names":["X-Actor"]})
        engine.verify_identity(self.project,{"operation_id":self.identity["id"],"session_id":sessions["bob"],
            "subject_selector":"/id","roles_selector":"/roles","tenant_selector":"/tenant"})
        op=engine.register_operation(self.project,{"url":self.base+"/items/owned-1","method":"GET","auth":"authenticated"})
        calls=self.server.calls
        with self.assertRaisesRegex(EngineError,"verified session"):
            engine.capture(self.project,{"operation_id":op["id"],"session_id":sessions["bob"],"headers":{"X-Actor":"alice"}})
        self.assertEqual(calls,self.server.calls)

    def test_semantic_negative_rejects_unchanged_input_and_confounder(self):
        op=engine.register_operation(self.project,{"url":self.base+"/search","method":"GET","auth":"public",
            "inputs":[{"name":"q","location":"query","selector":"q","consumer":"query"}]})
        engine.build_plan(self.project)
        ob=next(x for x in self.project.list("obligation") if x["kind"]=="input_test")
        for queries in [["q=a","q=a","q=control"],["q=a","q=b&other=changed","q=control"]]:
            ids=[engine.capture(self.project,{"operation_id":op["id"],"url":self.base+"/search?"+q})["id"] for q in queries]
            with self.assertRaises(EngineError) as caught:
                evaluate(self.project,{"obligation_id":ob["id"],"evidence_ids":ids,
                    "oracle":{"type":"semantic_negative","selector":"/items","baseline_expected":["same"],"control_expected":["different"]}})
            self.assertEqual("input_binding",caught.exception.code)
        self.assertEqual([],self.project.list("decision"))

    def test_transport_noise_selector_cannot_supply_sensitivity(self):
        op=engine.register_operation(self.project,{"url":self.base+"/search","method":"GET","auth":"public",
            "inputs":[{"name":"q","location":"query","selector":"q","consumer":"query"}]})
        engine.build_plan(self.project)
        ob=next(x for x in self.project.list("obligation") if x["kind"]=="input_test")
        ids=[engine.capture(self.project,{"operation_id":op["id"],"url":self.base+"/search?q="+q})["id"] for q in ["a","b","control"]]
        with self.assertRaisesRegex(EngineError,"Transport noise"):
            evaluate(self.project,{"obligation_id":ob["id"],"evidence_ids":ids,
                "oracle":{"type":"semantic_negative","selector":"/requestId","baseline_expected":"1","control_expected":"3"}})

    def test_input_semantics_change_reopens_new_obligation(self):
        hint={"url":self.base+"/search","method":"GET","auth":"public",
              "inputs":[{"name":"q","location":"query","selector":"q","consumer":"query"}]}
        op=engine.register_operation(self.project,hint)
        engine.build_plan(self.project)
        old=next(x for x in self.project.list("obligation") if x["kind"]=="input_test")
        ids=[engine.capture(self.project,{"operation_id":op["id"],"url":self.base+"/search?q="+q})["id"] for q in ["a","b","control"]]
        evaluate(self.project,{"obligation_id":old["id"],"evidence_ids":ids,
            "oracle":{"type":"semantic_negative","selector":"/items","baseline_expected":["same"],"control_expected":["different"]}})
        hint["inputs"][0]["consumer"]="template"
        engine.register_operation(self.project,hint)
        result=engine.build_plan(self.project)
        self.assertTrue(self.project.get("obligation",old["id"])["superseded"])
        self.assertEqual(0,result["evaluated"])
        self.assertTrue(any(g["kind"]=="input_test" and g["id"]!=old["id"] for g in result["gaps"]))

    def test_allowed_actor_has_normal_baseline_and_missing_admin_is_explicit(self):
        self.actors()
        result=engine.build_plan(self.project)
        self.assertTrue(any(g["kind"]=="baseline" and g.get("actor_id")=="alice" for g in result["gaps"]))
        op=engine.register_operation(self.project,{"url":self.base+"/admin","method":"GET","auth":"restricted","allowed_roles":["admin"]})
        result=engine.build_plan(self.project)
        self.assertTrue(any(g["kind"]=="identity_setup" and g["operation_id"]==op["id"] for g in result["gaps"]))

    def test_failed_analyst_finding_does_not_leave_orphan_decision(self):
        op=engine.register_operation(self.project,{"url":self.base+"/","method":"GET"})
        evidence=engine.capture(self.project,{"operation_id":op["id"]})
        with self.assertRaises(EngineError):
            record_finding(self.project,{"mode":"analyst","reviewer":"local-reviewer","reason":"fixture",
                "evidence_ids":[evidence["id"]],"title":"incomplete"})
        self.assertEqual([],self.project.list("decision"))

    def test_run_inspection_exposes_checkpoints_without_body(self):
        op=engine.register_operation(self.project,{"url":self.base+"/","method":"GET"})
        result=run_scenario(self.project,{"scenario":{"steps":[{"id":"read","operation_id":op["id"]}]}})
        public=dispatch(self.tmp.name,"run.inspect",{"project_id":"test","run_id":result["id"]})
        self.assertEqual("verified",public["checkpoints"][0]["status"])
        raw_fields = {"body", "body_base64", "body_file", "headers", "request", "response", "raw", "raw_request", "raw_response"}
        def check(value):
            if isinstance(value, dict):
                self.assertTrue(raw_fields.isdisjoint(value))
                for child in value.values():
                    check(child)
            elif isinstance(value, list):
                for child in value:
                    check(child)
        check(public)

    def test_state_failure_and_no_effect_do_not_refute(self):
        engine.create_project(self.tmp.name,{"project_id":"writes","target":self.base,"allow_mutation":True})
        with Project(self.tmp.name,"writes") as project:
            engine.add_actor(project,{"actor_id":"owner"})
            op=engine.register_operation(project,{"url":self.base+"/state","method":"POST","auth":"public","content_type":"application/json",
                "inputs":[{"name":"action","location":"body","selector":"/action","consumer":"state"}]})
            resource=engine.add_resource(project,{"operation_id":op["id"],"owner_actor_id":"owner","external_id":"owned",
                "request_binding":{"location":"body","selector":"/id"}})
            engine.build_plan(project)
            ob=next(x for x in project.list("obligation") if x["kind"]=="input_test")
            for status,action,expected in [(200,"mutate","confirmed"),(200,"noop","inconclusive"),(503,"noop",None)]:
                self.server.state="pending"
                self.server.write_status=status
                ids=[engine.capture(project,{"operation_id":op["id"],"resource_id":resource["id"],"effect":"test_resource_write",
                    "body":{"id":"owned","action":a}})["id"] for a in ["inspect",action,"inspect"]]
                args={"obligation_id":ob["id"],"evidence_ids":ids,"oracle":{"type":"state_invariant","selector":"/state",
                    "before_expected":"pending","forbidden_after":"approved"}}
                if expected:
                    self.assertEqual(expected,evaluate(project,args)["outcome"])
                else:
                    with self.assertRaisesRegex(EngineError,"successful business responses"):
                        evaluate(project,args)
            engine.register_operation(project,{"url":self.base+"/state","method":"POST","auth":"public","content_type":"application/json",
                "inputs":[{"name":"never_sent","location":"body","selector":"/never_sent","consumer":"state"}]})
            engine.build_plan(project)
            missing=next(x for x in project.list("obligation") if x.get("input_selector")=="/never_sent")
            self.server.write_status=200
            ids=[engine.capture(project,{"operation_id":op["id"],"resource_id":resource["id"],"effect":"test_resource_write",
                "body":{"id":"owned","action":"inspect"}})["id"] for _ in range(3)]
            with self.assertRaises(EngineError) as caught:
                evaluate(project,{"obligation_id":missing["id"],"evidence_ids":ids,"oracle":{"type":"state_invariant",
                    "selector":"/state","before_expected":self.server.state,"max_delta":0}})
            self.assertEqual("input_binding",caught.exception.code)


if __name__=="__main__":
    unittest.main()
