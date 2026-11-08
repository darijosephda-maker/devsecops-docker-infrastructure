import os, re
from flask import Flask, jsonify, request, Response
from flask_cors import CORS
import subprocess, json, urllib.request, re, os, threading, time

app = Flask(__name__)
CORS(app)

SERVICES_YML = '/traefik/dynamic/services.yml'
BUILDS_DIR = '/tmp/builds'
os.makedirs(BUILDS_DIR, exist_ok=True)

def docker_inspect(name):
    r = subprocess.run(['docker','inspect',name], capture_output=True, text=True)
    try: return json.loads(r.stdout)[0]
    except: return {}

def read_domains():
    domains = []
    seen = set()
    try:
        with open(SERVICES_YML,'r') as f: content = f.read()
        matches = re.findall(r'Host\(`([^`]+)`\)', content)
        for fqdn in matches:
            if fqdn in seen: continue
            seen.add(fqdn)
            sub = fqdn.split('.')[0]
            domains.append({'domain':fqdn,'sub':sub,'container':sub,'ip':'192.168.122.232','port':'80','status':'active'})
    except: pass
    return domains

@app.route('/api/containers')
def get_containers():
    try:
        result = subprocess.run(
            ['docker','ps','--format','{{.Names}}|||{{.Image}}|||{{.Status}}|||{{.Ports}}|||{{.Networks}}'],
            capture_output=True, text=True)
        domain_map = {d['sub']:d['domain'] for d in read_domains()}
        containers = []
        for line in result.stdout.strip().split('\n'):
            if not line: continue
            parts = line.split('|||')
            if len(parts) < 5: continue
            name, image, status, ports, network = parts
            insp = docker_inspect(name)
            health = insp.get('State',{}).get('Health',{}).get('Status','')
            final_status = health if health in ['healthy','unhealthy'] else ('running' if 'Up' in status else 'stopped')
            host_cfg = insp.get('HostConfig',{})
            mem = host_cfg.get('Memory',0)
            cpu_quota = host_cfg.get('CpuQuota',0)
            cpu_period = host_cfg.get('CpuPeriod',100000) or 100000
            ram_str = str(round(mem/1048576))+'m' if mem>0 else '—'
            cpu_str = str(round(cpu_quota/cpu_period,1)) if cpu_quota>0 else '—'
            domain = '—'
            for key,fqdn in domain_map.items():
                if key in name.lower(): domain=fqdn; break
            containers.append({
                'name':name,'image':image,'status':final_status,
                'domain':domain,'network':network,
                'ram':ram_str,'cpu':cpu_str,'ports':ports
            })
        return jsonify(containers)
    except Exception as e:
        return jsonify({'error':str(e)}), 500

@app.route('/api/stats')
def get_stats():
    try:
        r = subprocess.run(['docker','ps','-q'], capture_output=True, text=True)
        total = len([l for l in r.stdout.strip().split('\n') if l])
        return jsonify({'total':total,'healthy':total})
    except Exception as e:
        return jsonify({'error':str(e)}), 500

@app.route('/api/alerts')
def get_alerts():
    try:
        req = urllib.request.urlopen('http://172.17.0.1:9093/api/v2/alerts', timeout=3)
        data = json.loads(req.read())
        active = [a for a in data if a.get('status',{}).get('state')=='active']
        return jsonify({'count':len(active)})
    except: return jsonify({'count':0})

@app.route('/api/cve')
def get_cve():
    try:
        import base64
        creds = base64.b64encode(os.environ['HARBOR_CREDENTIALS'].encode()).decode()
        url = 'http://172.17.0.1/api/v2.0/projects/library/repositories/ubuntu-uts/artifacts/22.04?with_scan_overview=true'
        req = urllib.request.Request(url, headers={'Authorization': 'Basic ' + creds})
        data = json.loads(urllib.request.urlopen(req, timeout=5).read())
        overview = data.get('scan_overview', {})
        report = overview.get('application/vnd.security.vulnerability.report; version=1.1', {})
        summary = report.get('summary', {}).get('summary', {})
        return jsonify({'critical': summary.get('Critical', 0)})
    except: return jsonify({'critical': 0})

@app.route('/api/health')
def health():
    return jsonify({'status':'ok'})

@app.route('/api/logs/<name>')
def get_logs(name):
    try:
        r = subprocess.run(['docker','logs','--tail','200','--timestamps',name],
            capture_output=True, text=True)
        return jsonify({'logs':r.stdout+r.stderr,'name':name})
    except Exception as e:
        return jsonify({'logs':str(e),'name':name})

@app.route('/api/logs/stream/<name>')
def stream_logs(name):
    def generate():
        proc = subprocess.Popen(
            ['docker','logs','--tail','50','--follow','--timestamps',name],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            for line in proc.stdout:
                yield f"data: {json.dumps({'line':line.rstrip()})}\n\n"
        except GeneratorExit:
            proc.kill()
    return Response(generate(), mimetype='text/event-stream',
        headers={'Cache-Control':'no-cache','X-Accel-Buffering':'no'})

VERSIONS_FILE = '/tmp/container_versions.json'

def _load_versions():
    try:
        with open(VERSIONS_FILE,'r') as f: return json.load(f)
    except: return {}

def _save_version(name, data):
    versions = _load_versions()
    if name not in versions: versions[name] = []
    versions[name].append({'data':data,'ts':time.time()})
    versions[name] = versions[name][-5:]
    with open(VERSIONS_FILE,'w') as f: json.dump(versions, f)

def build_docker_cmd(name, data, tmp_name=None):
    ram   = (data.get('ram','512m') or '512m').strip()
    cpu   = str(data.get('cpu','0.5') or '0.5').strip()
    image = (data.get('image','nginx:alpine') or 'nginx:alpine').strip()
    net   = (data.get('network','bridge') or 'bridge').strip()
    port  = str(data.get('port','80') or '80').strip()
    sub   = (data.get('sub',name) or name).strip()
    fqdn  = f"{sub}.uts.bf"
    vol   = data.get('vol','')
    envs  = data.get('envs',[])
    hc    = data.get('healthcheck','')
    restart = data.get('restart','unless-stopped') or 'unless-stopped'
    cname = tmp_name or name
    cmd = ['docker','run','-d',
           '--name', cname,
           '--memory', ram,
           '--cpus', cpu,
           '--network', net,
           '--restart', restart,
           '-l','traefik.enable=true',
           '-l',f'traefik.http.routers.{sub}.rule=Host(`{fqdn}`)',
           '-l',f'traefik.http.services.{sub}.loadbalancer.server.port={port}']
    for e in envs:
        if e.strip(): cmd += ['-e', e.strip()]
    if vol: cmd += ['-v', vol]
    if hc:  cmd += ['--health-cmd', hc, '--health-interval','30s','--health-retries','3']
    cmd.append(image)
    return cmd

@app.route('/api/containers/create', methods=['POST'])
def create_container():
    try:
        data = request.get_json()
        name = data.get('name','').strip()
        if not name: return jsonify({'success':False,'error':'Nom obligatoire'}), 400
        cmd = build_docker_cmd(name, data)
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            _save_version(name, data)
            return jsonify({'success':True,'id':result.stdout.strip()[:12]})
        return jsonify({'success':False,'error':result.stderr.strip()}), 400
    except Exception as e:
        return jsonify({'success':False,'error':str(e)}), 500

@app.route('/api/containers/update/<name>', methods=['POST'])
def update_container(name):
    try:
        data = request.get_json()
        tmp = name + '_tmp_new'
        insp = docker_inspect(name)
        if insp:
            old_data = {
                'image': insp.get('Config',{}).get('Image',''),
                'network': list(insp.get('NetworkSettings',{}).get('Networks',{}).keys())[0] if insp.get('NetworkSettings',{}).get('Networks') else 'bridge',
            }
            _save_version(name, old_data)
        cmd = build_docker_cmd(name, data, tmp_name=tmp)
        test = subprocess.run(cmd, capture_output=True, text=True)
        if test.returncode != 0:
            return jsonify({'success':False,'error':test.stderr.strip()}), 400
        subprocess.run(['docker','stop',name], capture_output=True)
        subprocess.run(['docker','rm',name], capture_output=True)
        subprocess.run(['docker','rename',tmp,name], capture_output=True)
        return jsonify({'success':True,'id':test.stdout.strip()[:12]})
    except Exception as e:
        subprocess.run(['docker','rm','-f',name+'_tmp_new'], capture_output=True)
        return jsonify({'success':False,'error':str(e)}), 500

@app.route('/api/containers/delete/<name>', methods=['DELETE'])
def delete_container(name):
    try:
        subprocess.run(['docker','stop',name], capture_output=True)
        r = subprocess.run(['docker','rm',name], capture_output=True, text=True)
        if r.returncode == 0: return jsonify({'success':True})
        return jsonify({'success':False,'error':r.stderr.strip()}), 400
    except Exception as e:
        return jsonify({'success':False,'error':str(e)}), 500

@app.route('/api/containers/versions/<name>')
def get_versions(name):
    versions = _load_versions()
    return jsonify(versions.get(name, []))

@app.route('/api/containers/rollback/<name>', methods=['POST'])
def rollback_container(name):
    try:
        data = request.get_json()
        version_data = data.get('version_data',{})
        if not version_data: return jsonify({'success':False,'error':'Pas de version'}), 400
        tmp = name+'_rollback_tmp'
        cmd = build_docker_cmd(name, version_data, tmp_name=tmp)
        test = subprocess.run(cmd, capture_output=True, text=True)
        if test.returncode != 0:
            return jsonify({'success':False,'error':test.stderr.strip()}), 400
        subprocess.run(['docker','stop',name], capture_output=True)
        subprocess.run(['docker','rm',name], capture_output=True)
        subprocess.run(['docker','rename',tmp,name], capture_output=True)
        return jsonify({'success':True})
    except Exception as e:
        subprocess.run(['docker','rm','-f',name+'_rollback_tmp'], capture_output=True)
        return jsonify({'success':False,'error':str(e)}), 500

build_logs = {}

def _run_build(build_id, name, repo_url, branch, image_tag, sub, port, network, envs):
    logs = []
    def log(msg, t='info'):
        logs.append({'msg':msg,'type':t,'ts':time.time()})
        build_logs[build_id]['logs'] = logs[:]
    try:
        build_logs[build_id] = {'status':'running','logs':[]}
        work_dir = f"{BUILDS_DIR}/{build_id}"
        log(f"[GIT] Clonage de {repo_url} (branche {branch})...")
        r = subprocess.run(['git','clone','--branch',branch,'--depth','1',repo_url,work_dir],
            capture_output=True, text=True)
        if r.returncode != 0:
            log(f"[ERR] {r.stderr}",'err'); build_logs[build_id]['status']='failed'; return
        log("[GIT] Clonage terminé ✓",'ok')
        registry = '192.168.122.232/library'
        full_tag = f"{registry}/{image_tag}"
        log(f"[BUILD] Construction image {full_tag}...")
        r = subprocess.run(['docker','build','-t',full_tag,work_dir], capture_output=True, text=True)
        if r.returncode != 0:
            log(f"[ERR] {r.stderr}",'err'); build_logs[build_id]['status']='failed'; return
        log("[BUILD] Image construite ✓",'ok')
        log(f"[PUSH] Push vers Harbor...")
        r = subprocess.run(['docker','push',full_tag], capture_output=True, text=True)
        if r.returncode != 0: log("[WARN] Push Harbor échoué (déploiement local)",'warn')
        else: log("[PUSH] Image poussée ✓",'ok')
        log(f"[DEPLOY] Déploiement de {name}...")
        subprocess.run(['docker','stop',name], capture_output=True)
        subprocess.run(['docker','rm',name], capture_output=True)
        deploy_data = {'image':full_tag,'ram':'512m','cpu':'0.5','network':network,'port':port,'sub':sub,'envs':envs}
        cmd = build_docker_cmd(name, deploy_data)
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            log(f"[ERR] {r.stderr}",'err'); build_logs[build_id]['status']='failed'; return
        log(f"[OK] {name} déployé sur {sub}.uts.bf ✓",'ok')
        build_logs[build_id]['status'] = 'success'
        subprocess.run(['rm','-rf',work_dir], capture_output=True)
    except Exception as e:
        log(f"[ERR] {str(e)}",'err')
        build_logs[build_id]['status'] = 'failed'

@app.route('/api/build', methods=['POST'])
def build_from_git():
    try:
        data = request.get_json()
        repo_url = data.get('repo_url','').strip()
        name     = data.get('name','').strip()
        if not repo_url or not name:
            return jsonify({'success':False,'error':'repo_url et name obligatoires'}), 400
        build_id = f"{name}_{int(time.time())}"
        build_logs[build_id] = {'status':'pending','logs':[]}
        t = threading.Thread(target=_run_build, args=(
            build_id, name, repo_url,
            data.get('branch','main'),
            data.get('image_tag',name+':latest'),
            data.get('sub',name),
            str(data.get('port','80')),
            data.get('network','bridge'),
            data.get('envs',[])
        ))
        t.daemon = True; t.start()
        return jsonify({'success':True,'build_id':build_id})
    except Exception as e:
        return jsonify({'success':False,'error':str(e)}), 500

@app.route('/api/build/status/<build_id>')
def build_status(build_id):
    return jsonify(build_logs.get(build_id, {'status':'not_found','logs':[]}))

@app.route('/api/secrets')
def list_secrets():
    try:
        r = subprocess.run(['docker','secret','ls','--format','{{.Name}}|||{{.CreatedAt}}'],
            capture_output=True, text=True)
        secrets = []
        for line in r.stdout.strip().split('\n'):
            if not line: continue
            parts = line.split('|||')
            secrets.append({'name':parts[0],'created':parts[1] if len(parts)>1 else ''})
        return jsonify(secrets)
    except: return jsonify([])

@app.route('/api/secrets/create', methods=['POST'])
def create_secret():
    try:
        data = request.get_json()
        name  = data.get('name','').strip()
        value = data.get('value','').strip()
        if not name or not value:
            return jsonify({'success':False,'error':'Nom et valeur obligatoires'}), 400
        if not re.fullmatch(r'[a-zA-Z0-9_.-]{1,64}', name):
            return jsonify({'success':False,'error':'Nom invalide'}), 400
        r = subprocess.run(['docker','secret','create',name,'-'],
            input=value, capture_output=True, text=True)
        if r.returncode == 0: return jsonify({'success':True})
        return jsonify({'success':False,'error':r.stderr.strip()}), 400
    except Exception as e:
        return jsonify({'success':False,'error':str(e)}), 500

@app.route('/api/secrets/delete/<name>', methods=['DELETE'])
def delete_secret(name):
    try:
        r = subprocess.run(['docker','secret','rm',name], capture_output=True, text=True)
        if r.returncode == 0: return jsonify({'success':True})
        return jsonify({'success':False,'error':r.stderr.strip()}), 400
    except Exception as e:
        return jsonify({'success':False,'error':str(e)}), 500

@app.route('/api/domains')
def get_domains():
    return jsonify(read_domains())

@app.route('/api/domains/add', methods=['POST'])
def add_domain():
    try:
        data = request.get_json()
        sub  = data.get('sub','').strip()
        ip   = data.get('ip','192.168.122.232')
        port = data.get('port','80')
        fqdn = f"{sub}.uts.bf"
        with open(SERVICES_YML,'r') as f: yml = f.read()
        if f'Host(`{fqdn}`)' in yml:
            return jsonify({'success':False,'error':'Domaine déjà existant'})
        router = f"\n    # ── {sub}\n    {sub}:\n      rule: \"Host(`{fqdn}`)\"\n      service: {sub}\n      entryPoints:\n        - websecure\n      tls: {{}}"
        service = f"\n    {sub}:\n      loadBalancer:\n        servers:\n          - url: \"http://{ip}:{port}\""
        yml = yml.replace('  routers:', '  routers:'+router)
        yml = yml.replace('  services:', '  services:'+service)
        with open(SERVICES_YML,'w') as f: f.write(yml)
        return jsonify({'success':True,'fqdn':fqdn})
    except Exception as e:
        return jsonify({'success':False,'error':str(e)}), 500

@app.route('/api/domains/update', methods=['POST'])
def update_domain():
    try:
        data = request.get_json()
        sub  = data.get('sub','').strip()
        ip   = data.get('ip','192.168.122.232')
        port = data.get('port','80')
        with open(SERVICES_YML,'r') as f: yml = f.read()
        yml = re.sub(
            rf'(    {sub}:\n      loadBalancer:\n        servers:\n          - url: )"http://[^"]*"',
            rf'\1"http://{ip}:{port}"', yml)
        with open(SERVICES_YML,'w') as f: f.write(yml)
        return jsonify({'success':True,'fqdn':f'{sub}.uts.bf'})
    except Exception as e:
        return jsonify({'success':False,'error':str(e)}), 500

@app.route('/api/domains/delete/<sub>', methods=['DELETE'])
def delete_domain(sub):
    try:
        with open(SERVICES_YML,'r') as f: yml = f.read()
        if f'{sub}.uts.bf' not in yml:
            return jsonify({'success':False,'error':'Domaine introuvable'}), 404
        yml = re.sub(rf'\n    # ── {sub}\n    {sub}:\n      rule:[^\n]*\n      service:[^\n]*\n      entryPoints:\n        - websecure\n      tls: \{{\}}\n?','', yml)
        yml = re.sub(rf'\n    {sub}:\n      loadBalancer:\n        servers:\n          - url:[^\n]*\n?','', yml)
        with open(SERVICES_YML,'w') as f: f.write(yml)
        return jsonify({'success':True})
    except Exception as e:
        return jsonify({'success':False,'error':str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
