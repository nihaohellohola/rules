#!/usr/bin/env python3
"""Fetch every .lpx in the upstream directory and convert supported Loon rules to Egern YAML."""
from __future__ import annotations
import json, re, urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
API='https://api.github.com/repos/fkingikelee/fkikelee/contents/lpx'
RAW='https://raw.githubusercontent.com/fkingikelee/fkikelee/main/lpx/'
OUT=ROOT/'egern/modules'
def fetch(url):
    req=urllib.request.Request(url,headers={'User-Agent':'rules-lpx-sync','Accept':'application/vnd.github+json'})
    with urllib.request.urlopen(req,timeout=45) as r:return r.read().decode('utf-8-sig')
def q(s):return json.dumps(s,ensure_ascii=False)
def parse(text,filename):
    meta={}; sections={}; section=''
    for raw in text.splitlines():
        line=raw.strip()
        m=re.match(r'^#!([\w-]+)\s*=\s*(.*?)\s*$',line)
        if m:meta[m.group(1).lower()]=m.group(2);continue
        if not line or line.startswith(('#',';')):continue
        m=re.match(r'^\[([^]]+)\]',line)
        if m:section=m.group(1).strip().lower();sections.setdefault(section,[]);continue
        sections.setdefault(section,[]).append(line)
    scripts=[]; hosts=[]; rewrites=[]; issues=[]
    for line in sections.get('mitm',[]):
        m=re.match(r'hostname\s*=\s*(.*)',line,re.I)
        if m:hosts.extend(x.strip() for x in m.group(1).split(',') if x.strip())
    for line in sections.get('script',[]):
        # Loon request/response script entries, preserving URL, regex, tag and body requirement.
        m=re.match(r"(response|request)\s+if\s+(.+?)\s+then\s+script\(\s*(['\"])(.*?)\3\s*\)(.*)$",line,re.I)
        if not m:
            issues.append('unsupported script: '+line);continue
        kind,condition,_,url,opts=m.groups();condition=condition.strip()
        condition=re.sub(r'^\$\{url\}\s*(?:~=|=)\s*','',condition)
        tag=re.search(r"\btag\s*=\s*(['\"])(.*?)\1",opts)
        body=re.search(r'\brequires_body\s*=\s*(true|false)',opts,re.I)
        e={'type':'http_response' if kind.lower()=='response' else 'http_request','match':condition,'script_url':url}
        if tag:e['name']=tag.group(2)
        if body:e['body_required']=body.group(1).lower()=='true'
        scripts.append(e)
    # Loon rewrite rules: regex URL reject/redirect/modify headers are not equivalent to Egern scriptings;
    # map supported URL reject/redirect rules explicitly and report unhandled transformations.
    for line in sections.get('rewrite',[]):
        parts=line.split()
        if len(parts)>=3 and parts[1].lower() in ('reject','reject-200','reject-img','reject-dict','reject-array','reject-html','reject-drop'):
            rewrites.append({'match':parts[0],'action':parts[1].lower()})
        elif len(parts)>=3 and parts[1].lower() in ('302','307','redirect'):
            rewrites.append({'match':parts[0],'action':'redirect','to':parts[2]})
        else:issues.append('unsupported rewrite: '+line)
    if not scripts and not rewrites and not hosts:
        raise ValueError('No convertible script, rewrite, or MITM hostname rules')
    lines=[]
    for key,outkey in [('name','name'),('desc','description'),('author','author'),('icon','icon')]:
        if meta.get(key):lines.append(f'{outkey}: {q(meta[key])}')
    if not any(x.startswith('name:') for x in lines):lines.insert(0,'name: '+q(Path(filename).stem))
    if hosts:
        lines+=['mitm:','  hostnames:']+['    - '+q(x) for x in dict.fromkeys(hosts)]
    if scripts:
        lines.append('scriptings:')
        for e in scripts:
            lines.append('  - '+e['type']+':')
            for k in ('name','match','script_url','body_required'):
                if k in e:lines.append('      '+k+': '+(q(e[k]) if isinstance(e[k],str) else str(e[k]).lower()))
    if rewrites:
        lines.append('http:')
        lines.append('  rewrite:')
        for e in rewrites:
            lines+=['    - '+q(e['match'])+':']
            if e['action']=='redirect':lines.append('        redirect: '+q(e['to']))
            else:lines.append('        ' + e['action'] + ': true')
    return '\n'.join(lines)+'\n',issues

def main():
    listing=json.loads(fetch(API)); entries=[x for x in listing if x.get('type')=='file' and x.get('name','').lower().endswith('.lpx')]
    if not entries:raise SystemExit('Upstream API returned no .lpx files; refusing to delete existing modules')
    OUT.mkdir(parents=True,exist_ok=True); done=[]; failed=[]
    for item in sorted(entries,key=lambda x:x['name'].lower()):
        try:
            source=fetch(item.get('download_url') or RAW+item['name']); yaml,issues=parse(source,item['name'])
            target=OUT/(Path(item['name']).stem+'.yaml');target.write_text(yaml,encoding='utf-8')
            done.append(item['name']);print('CONVERTED',item['name'],'warnings='+str(len(issues)))
            for issue in issues:print('WARNING',item['name'],issue)
        except Exception as exc:failed.append((item['name'],str(exc)));print('FAILED',item['name'],exc)
    (ROOT/'scripts'/'egern_lpx_sources.json').write_text(json.dumps([{'name':x['name'],'url':x.get('download_url') or RAW+x['name'],'output':'egern/modules/'+Path(x['name']).stem+'.yaml'} for x in entries],ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(f'SUMMARY total={len(entries)} converted={len(done)} failed={len(failed)}')
    if failed:raise SystemExit(1)
if __name__=='__main__':main()
