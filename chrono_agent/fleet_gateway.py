# Chrono Agent  (c) 2026 Abdul Manan.  Source-available; see LICENSE.
# Resale or offering as a hosted service is prohibited.  All rights reserved.
"""Authenticated local fleet pilot: OpenAI chat + Anthropic Messages adapters.
Only routed non-streaming tool calls are inspected; this is not an OS monitor.
"""
import hmac
import json
import os
import threading
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from .fleet import Fleet, canonical

MAX_BYTES=4*1024*1024
ADAPTERS={'/v1/chat/completions','/v1/messages'}

class Gateway:
    def __init__(self,root='.',upstream=None,webhook=None):
        self.fleet=Fleet(root)
        self.upstream=(upstream or '').rstrip('/')
        if upstream and not upstream.startswith(('https://','http://127.0.0.1:','http://localhost:')):
            raise ValueError('Upstream must use HTTPS (or loopback HTTP for local models)')
        self.webhook=webhook
        if webhook and not webhook.startswith(('https://','http://127.0.0.1:','http://localhost:')):
            raise ValueError('Webhook must use HTTPS or loopback HTTP')
        self.token=os.environ.get('CHRONO_GATEWAY_TOKEN','')
        self.admin=os.environ.get('CHRONO_ADMIN_TOKEN','')
        if len(self.token)<24 or len(self.admin)<24 or self.admin==self.token:
            raise ValueError('Set distinct CHRONO_GATEWAY_TOKEN and CHRONO_ADMIN_TOKEN (at least 24 characters)')
        self.jobs=[]

    def notify(self,agent,result):
        if not self.webhook or not result.get('new_approval'):
            return
        item={'text':'ChronoAgent approval required for '+agent,'approval_id':result['approval_id'],'agent':agent,'score':result['score']}
        def send():
            outcome='sent'
            try:
                req=urllib.request.Request(self.webhook,data=canonical(item).encode(),headers={'Content-Type':'application/json'})
                with urllib.request.urlopen(req,timeout=10) as res:
                    res.read(1024)
            except Exception:
                outcome='failed'
            with self.fleet.db() as db:
                self.fleet.event(db,agent,'webhook.'+outcome,{'id':result['approval_id']})
        t=threading.Thread(target=send,daemon=True); self.jobs.append(t); t.start()

    def inspect(self,body,agent,path):
        if not isinstance(body,dict):
            raise ValueError('Malformed upstream reply')
        if path=='/v1/chat/completions':
            choices=body.get('choices')
            if not isinstance(choices,list) or not choices:
                raise ValueError('Unknown OpenAI reply shape')
            for choice in choices:
                msg=choice.get('message')
                if not isinstance(msg,dict):
                    raise ValueError('Missing message')
                calls=msg.get('tool_calls',[])
                if msg.get('function_call'):
                    raise ValueError('Legacy function_call is unsupported; use tool_calls')
                if not isinstance(calls,list):
                    raise ValueError('Malformed tool calls')
                for call in calls:
                    fn=call.get('function',{})
                    if call.get('type')!='function' or not isinstance(fn.get('name'),str) or not isinstance(fn.get('arguments'),str):
                        raise ValueError('Unknown tool format')
                    args=json.loads(fn['arguments'])
                    result=self.fleet.decision(agent,{'tool':fn['name'],'arguments':args})
                    self.notify(agent,result)
                    if result['blocked']:
                        return result
        else:
            if body.get('type')!='message' or not isinstance(body.get('content'),list):
                raise ValueError('Unknown Anthropic reply shape')
            for block in body['content']:
                if block.get('type')=='tool_use':
                    if not isinstance(block.get('name'),str) or not isinstance(block.get('input'),dict):
                        raise ValueError('Malformed Anthropic tool')
                    result=self.fleet.decision(agent,{'tool':block['name'],'arguments':block['input']})
                    self.notify(agent,result)
                    if result['blocked']:
                        return result
        return None

    def server(self,host='127.0.0.1',port=8787):
        if host not in ('127.0.0.1','localhost'):
            raise ValueError('Pilot binds loopback only; deploy behind authenticated TLS infrastructure for remote use')
        gw=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def reply(self,status,body,ctype='application/json'):
                data=body if isinstance(body,bytes) else canonical(body).encode()
                self.send_response(status)
                self.send_header('Content-Type',ctype)
                self.send_header('Content-Length',str(len(data)))
                self.send_header('Cache-Control','no-store')
                self.send_header('X-Content-Type-Options','nosniff')
                self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; frame-ancestors 'none'")
                self.end_headers(); self.wfile.write(data)
            def auth(self,admin=False):
                value=self.headers.get('X-Chrono-Token','')
                if not hmac.compare_digest(value,gw.admin if admin else gw.token):
                    self.reply(401,{'error':{'type':'chrono_auth','message':'Invalid Chrono credential'}})
                    return False
                return True
            def do_GET(self):
                if self.path=='/chrono/dashboard':
                    from .fleet_dashboard import PAGE
                    return self.reply(200,PAGE.encode(),'text/html; charset=utf-8')
                if not self.auth(admin=True): return
                if self.path=='/chrono/state': return self.reply(200,gw.fleet.state())
                self.reply(404,{'error':'Unknown endpoint'})
            def do_POST(self):
                try:
                    admin=self.path=='/chrono/approvals/decide'
                    if not self.auth(admin): return
                    if self.headers.get('Transfer-Encoding'):
                        raise ValueError('Chunked requests unsupported')
                    n=int(self.headers.get('Content-Length','0'))
                    if not 0<n<=MAX_BYTES: raise ValueError('Body missing or too large')
                    self.connection.settimeout(30)
                    body=json.loads(self.rfile.read(n))
                    if not isinstance(body,dict): raise ValueError('JSON object required')
                    if admin:
                        if type(body.get('approve')) is not bool: raise ValueError('approve must be boolean')
                        gw.fleet.decide(body.get('id'),body['approve'],body.get('actor'))
                        return self.reply(200,{'ok':True})
                    if self.path not in ADAPTERS and self.path!='/chrono/check':
                        return self.reply(404,{'error':'Unsupported adapter; use /chrono/check for custom executors'})
                    agent=self.headers.get('X-Chrono-Agent','')
                    # Explicit stable identity avoids incorrectly merging agents
                    # that share model names, IP addresses or provider API keys.
                    gw.fleet.touch(agent,body.get('model',''))
                    if self.path=='/chrono/check':
                        action=body.get('action')
                        if not isinstance(action,dict): raise ValueError('Structured action required')
                        result=gw.fleet.decision(agent,action); gw.notify(agent,result)
                        return self.reply(200,result)
                    if body.get('stream'):
                        return self.reply(400,{'error':{'type':'chrono_unsupported','message':'Streaming refused: use stream=false'}})
                    if not gw.upstream: raise ValueError('No upstream configured')
                    headers={'Content-Type':'application/json','Accept-Encoding':'identity'}
                    for key in ('Authorization','x-api-key','anthropic-version','anthropic-beta'):
                        if self.headers.get(key): headers[key]=self.headers[key]
                    req=urllib.request.Request(gw.upstream+self.path,data=canonical(body).encode(),headers=headers)
                    try:
                        with urllib.request.urlopen(req,timeout=120) as res:
                            data=res.read(MAX_BYTES+1)
                    except urllib.error.HTTPError as e:
                        return self.reply(e.code,{'error':{'type':'chrono_upstream','message':'Provider rejected request'}})
                    except urllib.error.URLError:
                        return self.reply(502,{'error':{'type':'chrono_upstream','message':'Provider unavailable'}})
                    if len(data)>MAX_BYTES: raise ValueError('Upstream response too large')
                    try:
                        result=gw.inspect(json.loads(data),agent,self.path)
                    except (ValueError,TypeError,AttributeError,KeyError):
                        return self.reply(502,{'error':{'type':'chrono_uninspected','message':'Reply format unsupported; nothing delivered'}})
                    if result:
                        return self.reply(403,{'error':{'type':'chrono_policy','message':'Tool response withheld by policy','decision':result['action'],'score':result['score'],'approval_id':result.get('approval_id')}})
                    self.reply(200,data)
                except (ValueError,TypeError,KeyError,AttributeError) as e:
                    self.reply(400,{'error':str(e)})
                except (RuntimeError,OSError,sqlite_error):
                    self.reply(503,{'error':'Chrono control unavailable; action refused'})
        import sqlite3
        sqlite_error=sqlite3.Error
        server=ThreadingHTTPServer((host,port),Handler)
        server.daemon_threads=True
        return server
