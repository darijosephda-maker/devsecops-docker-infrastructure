#!/usr/bin/env python3
import json, subprocess, urllib.request, yaml, os, re
from http.server import HTTPServer, BaseHTTPRequestHandler

SERVICES_YML = '/traefik/dynamic/services.yml'

def get_containers():
    r = subprocess.run(['docker','ps','--format','{{.Names}}'], capture_output=True, text=True)
    lines = [l for l in r.stdout.strip().split('\n') if l]
    return len(lines)

def get_alerts():
    try:
        r = urllib.request.urlopen('http://localhost:9093/api/v2/alerts', timeout=3)
        data = json.loads(r.read())
        active = [a for a in data if a.get('status',{}).get('state') == 'active']
        return len(active)
    except:
        return 0

def read_yml():
    with open(SERVICES_YML, 'r') as f:
        return yaml.safe_load(f.read())

def write_yml(data):
    with open(SERVICES_YML, 'w') as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True)

def get_domains():
    try:
        data = read_yml()
        routers = data.get('http', {}).get('routers', {})
        services = data.get('http', {}).get('services', {})
        result = []
        for name, router in routers.items():
            rule = router.get('rule', '')
            match = re.search(r'Host\(`([^`]+)`\)', rule)
            fqdn = match.group(1) if match else ''
            svc = services.get(name, {})
            servers = svc.get('loadBalancer', {}).get('servers', [{}])
            url = servers[0].get('url', '') if servers else ''
            ip_port = url.replace('http://', '').replace('https://', '')
            parts = ip_port.rsplit(':', 1)
            ip = parts[0] if parts else ''
            port = parts[1] if len(parts) > 1 else '80'
            sub = fqdn.split('.')[0] if fqdn else name
            result.append({'id': name, 'sub': sub, 'fqdn': fqdn,
                           'service': name, 'ip': ip, 'port': port, 'status': 'active'})
        return result
    except Exception as e:
        return []

def add_domain(sub, service, ip, port):
    fqdn = f"{sub}.uts.bf"
    data = read_yml()
    if 'http' not in data:
        data['http'] = {}
    if 'routers' not in data['http']:
        data['http']['routers'] = {}
    if 'services' not in data['http']:
        data['http']['services'] = {}
    if sub in data['http']['routers']:
        return False, 'Domaine déjà existant'
    data['http']['routers'][sub] = {
        'rule': f"Host(`{fqdn}`)",
        'service': sub,
        'entryPoints': ['websecure'],
        'tls': {}
    }
    data['http']['services'][sub] = {
        'loadBalancer': {'servers': [{'url': f"http://{ip}:{port}"}]}
    }
    write_yml(data)
    return True, fqdn

def update_domain(sub, ip, port):
    data = read_yml()
    if sub not in data.get('http', {}).get('services', {}):
        return False, 'Domaine introuvable'
    data['http']['services'][sub]['loadBalancer']['servers'] = [{'url': f"http://{ip}:{port}"}]
    write_yml(data)
    return True, f"{sub}.uts.bf"

def delete_domain(sub):
    data = read_yml()
    routers = data.get('http', {}).get('routers', {})
    services = data.get('http', {}).get('services', {})
    if sub not in routers:
        return False, 'Domaine introuvable'
    del routers[sub]
    if sub in services:
        del services[sub]
    write_yml(data)
    return True, sub

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def send_json(self, data, code=200):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def read_body(self):
        length = int(self.headers.get('Content-Length', 0))
        return json.loads(self.rfile.read(length)) if length else {}

    def do_GET(self):
        if self.path == '/api/stats':
            self.send_json({'total': get_containers()})
        elif self.path == '/api/alerts':
            self.send_json({'count': get_alerts()})
        elif self.path == '/api/cve':
            self.send_json({'critical': 0})
        elif self.path == '/api/domains':
            self.send_json(get_domains())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == '/api/domains/add':
            data = self.read_body()
            ok, msg = add_domain(
                data.get('sub',''),
                data.get('service',''),
                data.get('ip','192.168.122.232'),
                data.get('port','80')
            )
            self.send_json({'success': ok, 'fqdn' if ok else 'error': msg})
        elif self.path == '/api/domains/update':
            data = self.read_body()
            ok, msg = update_domain(data.get('sub',''), data.get('ip',''), data.get('port','80'))
            self.send_json({'success': ok, 'fqdn' if ok else 'error': msg})
        else:
            self.send_response(404)
            self.end_headers()

    def do_DELETE(self):
        if self.path.startswith('/api/domains/'):
            sub = self.path.split('/')[-1]
            ok, msg = delete_domain(sub)
            self.send_json({'success': ok, 'sub' if ok else 'error': msg})
        else:
            self.send_response(404)
            self.end_headers()

print("API demarree sur port 8889")
HTTPServer(('0.0.0.0', 8889), Handler).serve_forever()
