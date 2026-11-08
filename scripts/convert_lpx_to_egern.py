#!/usr/bin/env python3
"""Fetch every .lpx in the upstream directory and convert supported Loon rules to Egern YAML."""
from __future__ import annotations
import json, os, re, urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
API='https://api.github.com/repos/fkingikelee/fkikelee/contents/lpx'
RAW='https://raw.githubusercontent.com/fkingikelee/fkikelee/main/lpx/'
OUT=ROOT/'egern/modules'
def fetch(url):
    headers={'User-Agent':'rules-lpx-sync','Accept':'application/vnd.github+json'}
    token=os.environ.get('GITHUB_TOKEN')
    if token: headers['Authorization']='Bearer '+token
    req=urllib.request.Request(url,headers=headers)
    with urllib.request.urlopen(req,timeout=45) as r:return r.read().decode('utf-8-sig')
def q(s):return json.dumps(s,ensure_ascii=False)
def parse(text,filename):
    meta={}; sections={}; section=''
    for raw in text.splitlines():
        line=raw.strip()
        m=re.match(r'^#!([\\w-]+)\\s*=\\s*(.*?)\\s*$',line)
        if m:meta[m.group(1).lower()]=m.group(2);continue
        if not line or line.startswith(('#',';')):continue
        m=re.match(r'^\\[([^]]+)\\]',line)
        if m:section=m.group(1).strip().lower();sections.setdefault(section,[]);continue
        sections.setdefault(section,[]).append(line)
    scripts=[]; hosts=[]; rewrites=[]; issues=[]
    for line in sections.get('mitm',[]):
        m=re.match(r'hostname\\s*=\\s*(.*)',line,re.I)
        if m:hosts.extend(x.strip() for x in m.group(1).split(',') if x.strip())
    for line in sections.get('script',[]):
        m=re.match(r"(response|request)\\s+if\\s+(.+?)\\s+then\\s+script\\(\\s*(['\\\"])(.*?)\\3\\s*\\)(.*)$",line,re.I)
        if not m:
            issues.append('unsupported script: '+line);continue
        kind,condition,_,url,opts=m.groups();condition=condition.strip()
        condition=re.sub(r'^\\$\\{url\\}\\s*(?:~=|=)\\s*','',condition)
        tag=re.search(r"\\btag\\s*=\\s*(['\\\"])(.*?)\\1",opts)
        body=re.search(r'\\brequires_body\\s*=\\s*(true|false)',opts,re.I)
        e={'type':'http_response' if kind.lower()=='response' else 'http_request','match':condition,'script_url':url}
        if tag:e['name']=tag.group(2)
        if body:e['body_required']=body.group(1).lower()=='true'
        scripts.append(e)
    reject_map={'reject':'reject','reject_200':'reject-200','reject_dict':'reject-dict','reject_array':'reject-array','reject_img':'reject-img','reject_html':'reject-html','reject_drop':'reject-drop'}
    for line in sections.get('rewrite',[]):
        try:
            m=re.match(r'^(?:request|response)\\s+if\\s+(.+?)\\s+then\\s+(.+)$',line.strip(),re.I)
            if m:
                match,directive=m.groups()
                match=re.sub(r'^\\$\\{url\\}\\s*(?:~=|=)\\s*','',match.strip())
            else:
                parts=line.split()
                if len(parts)<2: raise ValueError('missing action')
                match,directive=parts[0],' '.join(parts[1:])
            call=re.fullmatch(r'([\\w-]+)(?:\\((.*?)\\))?',directive.strip(),re.I)
            if not call: raise ValueError('unknown directive')
            action,arg=call.groups(); normalized=action.lower().replace('-','_')
            if normalized in reject_map:
                rewrites.append({'match':match,'action':reject_map[normalized]})
            elif action.lower() in ('302','307','redirect'):
                to=(arg.strip(' \\"\\'') if arg else directive.split()[-1].strip(' \\"\\''))
                rewrites.append({'match':match,'action':'redirect','to':to})
            else: raise ValueError('unsupported action '+action)
        except Exception as exc: issues.append(f'unsupported rewrite (skipped): {line} ({exc})')
    if not scripts and not rewrites and not hosts:
        raise ValueError('No convertible script, rewrite, or MITM hostname rules')
    lines=[]
    for key,outkey in [('name','name'),('desc','description'),('author','author'),('icon','icon')]:
        if meta.get(key):lines.append(f'{outkey}: {q(meta[key])}')
    if not any(x.startswith('name:') for x in lines):lines.insert(0,'name: '+q(Path(filename).stem))
    if hosts:lines+=['mitm:','  hostnames:']+['    - '+q(x) for x in dict.fromkeys(hosts)]
    if scripts:
        lines.append('scriptings:')
        for e in scripts:
            lines.append('  - '+e['type']+':')
            for k in ('name','match','script_url','body_required'):
                if k in e:lines.append('      '+k+': '+(q(e[k]) if isinstance(e[k],str) else str(e[k]).lower()))
    if rewrites:
        lines+=['http:','  rewrite:']
        for e in rewrites:
            lines+=['    - '+q(e['match'])+':']
            if e['action']=='redirect':lines.append('        redirect: '+q(e['to']))
            else:lines.append('        '+e['action']+': true')
    return '\\n'.join(lines)+'\\n',issues

def main():
    try: listing=json.loads(fetch(API))
    except Exception as exc:
        print('ERROR unable to fetch upstream listing:',exc);return
    entries=[x for x in listing if x.get('type')=='file' and x.get('name','').lower().endswith('.lpx')]
    if not entries:
        print('WARNING upstream API returned no .lpx files; retaining existing modules');return
    OUT.mkdir(parents=True,exist_ok=True); done=[]; failed=[]
    for item in sorted(entries,key=lambda x:x['name'].lower()):
        try:
            source=fetch(item.get('download_url') or RAW+item['name']); output,issues=parse(source,item['name'])
            (OUT/(Path(item['name']).stem+'.yaml')).write_text(output,encoding='utf-8')
            done.append(item['name']);print('CONVERTED',item['name'],'warnings='+str(len(issues)))
            for issue in issues:print('WARNING',item['name'],issue)
        except Exception as exc:failed.append((item.get('name','?'),str(exc)));print('FAILED',item.get('name','?'),exc)
    try:
        (ROOT/'scripts'/'egern_lpx_sources.json').write_text(json.dumps([{'name':x['name'],'url':x.get('download_url') or RAW+x['name'],'output':'egern/modules/'+Path(x['name']).stem+'.yaml'} for x in entries],ensure_ascii=False,indent=2)+'\\n',encoding='utf-8')
    except Exception as exc: print('WARNING unable to write source manifest:',exc)
    print(f'SUMMARY total={len(entries)} converted={len(done)} failed={len(failed)}')
if __name__=='__main__':main()
