import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _home  # noqa: F401  (temporary Chrono home for keys and witnesses)
from chrono_agent import SnapshotStore
from chrono_agent.fleet import Fleet
from chrono_agent.fleet_gateway import Gateway

class FleetTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.base=Path(self.tmp.name)
        self.root=self.base/'control';self.root.mkdir();s=SnapshotStore(self.root);s.init();s.snapshot('init')
        self.f=Fleet(self.root)
    def tearDown(self):self.tmp.cleanup()
    def policy(self):
        (self.root/'chrono-policy.yaml').write_text('thresholds:\n  block: 70\n  approve: 40\n')
    def test_dynamic_counts_concurrent(self):
        for count in (2,5,15,40):
            with ThreadPoolExecutor(max_workers=8) as pool:
                list(pool.map(lambda i:self.f.touch('a'+str(i),'model'),range(count)))
            self.assertEqual(len(self.f.state()['agents']),count)
        self.assertTrue(self.f.state()['audit_intact'])
    def test_block_drop_and_allow_other_agent(self):
        self.f.touch('db');self.f.touch('support')
        self.assertEqual(self.f.decision('db',{'command':'DROP TABLE users'})['action'],'block')
        self.assertEqual(self.f.decision('support',{'command':'echo hello'})['action'],'allow')
    def test_approval_exact_action_single_use(self):
        self.policy();self.f.touch('db')
        action={'command':'sudo echo hi','target':'prod'}
        r=self.f.decision('db',action);self.assertEqual(r['action'],'approve')
        self.f.decide(r['approval_id'],True,'manan')
        self.assertEqual(self.f.decision('db',{'command':'sudo echo hi','target':'other'})['action'],'approve')
        self.assertEqual(self.f.decision('db',action)['action'],'allow')
        self.assertEqual(self.f.decision('db',action)['action'],'approve')
    def test_configured_human_approver_required(self):
        self.policy()
        with (self.root/'chrono-policy.yaml').open('a') as f:f.write('approvers:\n  - manan\n')
        self.f.touch('db');r=self.f.decision('db',{'command':'sudo echo hi'})
        with self.assertRaises(ValueError):self.f.decide(r['approval_id'],True,'other')
        self.f.decide(r['approval_id'],True,'manan')
        self.assertEqual(self.f.state()['approvals'][0]['actor'],'manan')
    def test_approval_expiry(self):
        self.policy();self.f.touch('db');a={'command':'sudo echo hi'}
        r=self.f.decision('db',a)
        with self.f.db() as db:db.execute('UPDATE approvals SET expires=0')
        with self.assertRaises(ValueError):self.f.decide(r['approval_id'],True,'manan')
    def test_lane_rollback_and_redo_only_one_agent(self):
        for agent in ('a','b'):
            path=self.base/agent;path.mkdir();(path/'app.txt').write_text('old');self.f.register(agent,path)
        sid=self.f.savepoint('a')['id']
        (self.base/'a/app.txt').write_text('mistake');(self.base/'b/app.txt').write_text('good-work')
        result=self.f.rollback('a',sid)
        self.assertEqual((self.base/'a/app.txt').read_text(),'old')
        self.assertEqual((self.base/'b/app.txt').read_text(),'good-work')
        self.f.rollback('a',result['redo'])
        self.assertEqual((self.base/'a/app.txt').read_text(),'mistake')
    def test_overlapping_workspace_rejected(self):
        p=self.base/'a';p.mkdir();(p/'nested').mkdir();self.f.register('a',p)
        with self.assertRaises(ValueError):self.f.register('b',p/'nested')
    def test_audit_tamper_detected(self):
        self.f.touch('a')
        with self.f.db() as db:db.execute("UPDATE events SET action='changed'")
        self.assertFalse(self.f.state()['audit_intact'])

class GatewayTests(FleetTests):
    def setUp(self):
        super().setUp()
        self.env=patch.dict(os.environ,{'CHRONO_GATEWAY_TOKEN':'g'*32,'CHRONO_ADMIN_TOKEN':'h'*32})
        self.env.start();self.hits=[];outer=self
        class Provider(BaseHTTPRequestHandler):
            def log_message(self,*a):pass
            def do_POST(self):
                b=json.loads(self.rfile.read(int(self.headers['Content-Length'])));outer.hits.append(b)
                if self.path=='/notify':outer.webhook_body=b;data=b'{}'
                elif self.path=='/v1/messages':data=json.dumps({'type':'message','content':[{'type':'tool_use','name':'shell','input':{'command':b['command']}}]}).encode()
                else:data=json.dumps({'choices':[{'message':{'tool_calls':[{'type':'function','function':{'name':'shell','arguments':json.dumps({'command':b['command']})}}]}}]}).encode()
                self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
        self.provider=ThreadingHTTPServer(('127.0.0.1',0),Provider)
        self.pt=threading.Thread(target=self.provider.serve_forever);self.pt.start()
        url='http://127.0.0.1:'+str(self.provider.server_port)
        self.gw=Gateway(self.root,url,url+'/notify');self.server=self.gw.server(port=0)
        self.gt=threading.Thread(target=self.server.serve_forever);self.gt.start()
        self.url='http://127.0.0.1:'+str(self.server.server_port)
    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.gt.join()
        for job in self.gw.jobs:job.join(15)
        self.provider.shutdown();self.provider.server_close();self.pt.join();self.env.stop();super().tearDown()
    def request(self,path,body=None,token='g'*32,agent='a'):
        req=urllib.request.Request(self.url+path,data=json.dumps(body).encode() if body is not None else None,headers={'X-Chrono-Token':token,'X-Chrono-Agent':agent})
        try:
            with urllib.request.urlopen(req) as r:return r.status,json.loads(r.read())
        except urllib.error.HTTPError as e:return e.code,json.loads(e.read())
    def test_real_http_two_provider_formats(self):
        for path in ('/v1/chat/completions','/v1/messages'):
            status,r=self.request(path,{'command':'rm -rf /','model':'test'})
            self.assertEqual(status,403);self.assertEqual(r['error']['score'],98)
            status,r=self.request(path,{'command':'echo hi','model':'test'},agent='b')
            self.assertEqual(status,200)
        status,state=self.request('/chrono/state',token='h'*32)
        self.assertEqual(status,200);self.assertEqual(len(state['agents']),2);self.assertTrue(state['audit_intact'])
    def test_unauthorized_request_never_reaches_provider(self):
        status,_=self.request('/v1/chat/completions',{'command':'echo hi'},token='wrong')
        self.assertEqual(status,401);self.assertEqual(self.hits,[])
    def test_streaming_refused_before_forwarding(self):
        status,_=self.request('/v1/chat/completions',{'command':'echo hi','stream':True})
        self.assertEqual(status,400);self.assertEqual(self.hits,[])
    def test_approval_webhook_and_authenticated_decision(self):
        self.policy();action={'command':'sudo echo hi'}
        status,r=self.request('/chrono/check',{'action':action})
        self.assertEqual(r['action'],'approve');aid=r['approval_id']
        for job in self.gw.jobs:job.join(15)
        self.assertEqual(self.webhook_body['approval_id'],aid)
        status,_=self.request('/chrono/approvals/decide',{'id':aid,'approve':True,'actor':'manan'})
        self.assertEqual(status,401)
        status,_=self.request('/chrono/approvals/decide',{'id':aid,'approve':True,'actor':'manan'},token='h'*32)
        self.assertEqual(status,200)
        self.assertEqual(self.request('/chrono/check',{'action':action})[1]['action'],'allow')
        self.assertEqual(self.request('/chrono/check',{'action':action})[1]['action'],'approve')
    def test_unsupported_adapter_refused(self):
        status,_=self.request('/v1/responses',{'command':'hi'})
        self.assertEqual(status,404);self.assertEqual(self.hits,[])

if __name__=='__main__':unittest.main()
