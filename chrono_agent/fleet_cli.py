"""Fleet pilot CLI commands; separate from the illustrative website."""
import json
from .fleet import Fleet

def run(a):
    fleet=Fleet('.')
    if a.fleet_action=='gateway':
        from .fleet_gateway import Gateway
        gw=Gateway('.',a.upstream,a.webhook)
        server=gw.server(port=a.port)
        print('Chrono fleet pilot: http://127.0.0.1:%d/chrono/dashboard'%a.port,flush=True)
        print('Only configured, non-streaming traffic is covered. Ctrl+C stops the service.',flush=True)
        try: server.serve_forever()
        except KeyboardInterrupt: pass
        finally: server.server_close()
    elif a.fleet_action=='list':
        print(json.dumps(fleet.state(),indent=2))
    elif a.fleet_action=='register':
        fleet.register(a.agent,a.workspace); print('Registered isolated workspace for '+a.agent)
    elif a.fleet_action=='savepoint':
        print(fleet.savepoint(a.agent)['id'])
    elif a.fleet_action=='rollback':
        if not a.yes:
            raise ValueError('Confirm explicit lane rollback with --yes (stop writers first)')
        print(json.dumps(fleet.rollback(a.agent,a.snapshot),indent=2))
    elif a.fleet_action=='decide':
        fleet.decide(a.id,a.decision=='approve',a.actor)
        print('Decision recorded by local administrator')

def install(sub):
    g=sub.add_parser('gateway',help='authenticated local model gateway pilot')
    gs=g.add_subparsers(dest='gateway_cmd',required=True)
    p=gs.add_parser('start');p.add_argument('--port',type=int,default=8787);p.add_argument('--upstream');p.add_argument('--webhook');p.set_defaults(f=run,fleet_action='gateway')
    f=sub.add_parser('fleet',help='dynamic agents and isolated workspace recovery')
    fs=f.add_subparsers(dest='fleet_cmd',required=True)
    fs.add_parser('list').set_defaults(f=run,fleet_action='list')
    p=fs.add_parser('register');p.add_argument('agent');p.add_argument('--workspace',required=True);p.set_defaults(f=run,fleet_action='register')
    p=fs.add_parser('savepoint');p.add_argument('agent');p.set_defaults(f=run,fleet_action='savepoint')
    p=fs.add_parser('rollback');p.add_argument('agent');p.add_argument('snapshot');p.add_argument('--yes',action='store_true');p.set_defaults(f=run,fleet_action='rollback')
    f=sub.add_parser('approvals',help='local-administrator approval commands')
    fs=f.add_subparsers(dest='approval_cmd',required=True)
    fs.add_parser('list').set_defaults(f=run,fleet_action='list')
    for decision in ('approve','deny'):
        p=fs.add_parser(decision);p.add_argument('id');p.add_argument('--by',dest='actor',required=True);p.set_defaults(f=run,fleet_action='decide',decision=decision)
