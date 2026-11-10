#!/usr/bin/env python3
"""Fetch every .lpx in the upstream directory and convert supported Loon rules to Egern YAML."""
from __future__ import annotations
import json, os, re, urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
API='https://api.github.com/repos/fkingikelee/fkikelee/contents/lpx'
RAW='https://raw.githubusercontent.com/fkingikelee/fkikelee/main/lpx/'
OUT=ROOT/'egern/modules'
WHITELIST=ROOT/'scripts'/'convert_whitelist.txt'
def load_whitelist():
    """Names (one per line, '#' comments, .lpx suffix optional). None = file missing or empty = convert all."""
    if not WHITELIST.exists():return None
    names=set()
    for line in WHITELIST.read_text(encoding='utf-8').splitlines():
        line=line.split('#',1)[0].strip()
        if line:names.add((line[:-4] if line.lower().endswith('.lpx') else line).lower())
    return names or None
def fetch(url):
    headers={'User-Agent':'rules-lpx-sync','Accept':'application/vnd.github+json'}
    token=os.environ.get('GITHUB_TOKEN')
    if token: headers['Authorization']='Bearer '+token
    req=urllib.request.Request(url,headers=headers)
    with urllib.request.urlopen(req,timeout=45) as r:return r.read().decode('utf-8-sig')
def q(s):return json.dumps(s,ensure_ascii=False)
def bare_regex(s):
    s=s.strip()
    if s.startswith('/'):
        i=len(s)-1
        while i>0:
            if s[i]=='/' and s[i-1]!='\\':break
            i-=1
        if i>0 and re.fullmatch(r'[a-zA-Z]*',s[i+1:]):return s[1:i]
    return s
def split_path(p):
    p=p.strip()
    if p.startswith('$.'):p=p[2:]
    parts=[]
    for seg in p.split('.'):
        seg=seg.strip()
        if seg.isdigit():parts.append(int(seg))
        elif seg:parts.append(seg)
    return parts
def split_top_level(s):
    parts=[];cur='';quote='';depth=0
    for ch in s:
        if quote:
            cur+=ch
            if ch==quote:quote=''
            continue
        if ch in ('"',"'"):quote=ch;cur+=ch
        elif ch=='{':depth+=1;cur+=ch
        elif ch=='}':depth-=1;cur+=ch
        elif ch==',' and depth==0:parts.append(cur);cur=''
        else:cur+=ch
    parts.append(cur)
    return [p.strip() for p in parts]
def unquote(s):
    s=s.strip()
    if len(s)>=2 and s[0]==s[-1] and s[0] in ('"',"'"):return s[1:-1]
    return None
RULE_TYPES={'DOMAIN':'domain','DOMAIN-SUFFIX':'domain_suffix','DOMAIN-KEYWORD':'domain_keyword','IP-CIDR':'ip_cidr','IP-CIDR6':'ip_cidr6','URL-REGEX':'url_regex','USER-AGENT':'user_agent','PROTOCOL':'protocol'}
def strip_parens(s):
    s=s.strip()
    if s.startswith('(') and s.endswith(')'):return s[1:-1].strip()
    return s
def split_paren(s):
    parts=[];cur='';depth=0;quote=''
    for ch in s:
        if quote:
            cur+=ch
            if ch==quote:quote=''
            continue
        if ch in ('"',"'"):quote=ch;cur+=ch
        elif ch=='(':depth+=1;cur+=ch
        elif ch==')':depth-=1;cur+=ch
        elif ch==',' and depth==0:parts.append(cur.strip());cur=''
        else:cur+=ch
    parts.append(cur.strip())
    return parts
def rule_node(kind,value):
    kind=kind.strip().upper()
    if kind in ('AND','OR'):
        subs=[]
        for sub in split_paren(strip_parens(value)):
            sp=split_paren(strip_parens(sub))
            subs.append(rule_node(sp[0],','.join(sp[1:])))
        return {'type':kind.lower(),'match':subs}
    if kind not in RULE_TYPES:raise ValueError('unsupported rule type '+kind)
    v=value.strip()
    if len(v)>=2 and v[0]==v[-1] and v[0] in ('"',"'"):v=v[1:-1]
    return {'type':RULE_TYPES[kind],'match':v.lower() if kind=='PROTOCOL' else v}
def rule_lines(node,indent,policy=None,no_resolve=False):
    pad=' '*indent
    key=pad+'    '
    out=[pad+'- '+node['type']+':']
    if isinstance(node['match'],list):
        out.append(key+'match:')
        for sub in node['match']:out+=rule_lines(sub,indent+6)
    else:out.append(key+'match: '+q(node['match']))
    if policy:out.append(key+'policy: '+policy)
    if no_resolve:out.append(key+'no_resolve: true')
    return out
def argument_defaults(lines):
    """Parse the Loon [Argument] section: key -> declared default value."""
    defaults={}
    for line in lines:
        m=re.match(r'^([^=]+?)\s*=\s*(select|switch|input|textarea)\s*,\s*(.*)$',line.strip(),re.I)
        if not m:continue
        key,kind,rest=m.group(1).strip(),m.group(2).lower(),m.group(3)
        head=re.split(r',\s*(?:tag|desc)\s*=',rest,maxsplit=1)[0]
        if kind=='select':
            vals=re.findall(r'"([^"]*)"|\'([^\']*)\'',head)
            default=next((a or b for a,b in vals),'')
        else:
            first=head.split(',',1)[0].strip()
            v=unquote(first)
            default=v if v is not None else first
        defaults[key]=default
    return defaults
def resolve_script_argument(text,defaults):
    """Turn a Loon script() second argument ({${a}, ${b}} or a quoted string) into a k=v&... string."""
    inner=text.strip()
    if not (inner.startswith('{') and inner.endswith('}')):
        v=unquote(inner)
        if v is None:return None,'unsupported script argument'
        return v,''
    body=inner[1:-1]
    if not body.strip():return '',''
    pairs=[]
    for m in re.finditer(r'\$\{([^{}]+)\}',body):
        name=m.group(1).strip()
        if name not in defaults:return None,'undeclared script argument '+name
        pairs.append(name+'='+defaults[name])
    if re.sub(r'\$\{[^{}]+\}','',body).strip(' ,'):return None,'unsupported script argument object'
    return '&'.join(pairs),''
def quartz_to_cron(expr):
    """Fold a 6-field Quartz-style cron into a 5-field one. Returns (cron, error)."""
    f=expr.split()
    if len(f)==5:return expr,None
    if len(f)!=6:return None,'not a standard 5-field cron expression: '+expr
    if f[0] not in ('0','*'):return None,'cron with second-level schedule cannot be converted: '+expr
    f=f[1:]
    for i in (2,4):
        if f[i]=='?':f[i]='*'
    f[0]=re.sub(r'^0/(\d+)$',r'*/\1',f[0])
    tok=re.compile(r'^(\*|\d+(-\d+)?)(/\d+)?(,(\*|\d+(-\d+)?)(/\d+)?)*$|^[A-Za-z]{3}(-[A-Za-z]{3})?(,[A-Za-z]{3}(-[A-Za-z]{3})?)*$')
    if not all(tok.match(x) for x in f):return None,'unsupported cron syntax: '+expr
    return ' '.join(f),None
def parse_script_line(line,defaults):
    """Parse one Loon v2 [Script] line into an Egern scriptings entry. Returns (entry, error, notes)."""
    m=re.match(r'^(request|response)\s+if\s+(.+?)\s+then\s+script\s*\((.*)\)\s*(?:with\s+(.*))?$',line,re.I)
    cron=False
    if m:trigger,inner,opts=m.group(2).strip(),m.group(3),m.group(4) or ''
    else:
        m=re.match(r'^cron\s+(.+?)\s+then\s+script\s*\((.*)\)\s*(?:with\s+(.*))?$',line,re.I)
        if not m:return None,'not a convertible script trigger',[]
        cron=True;trigger,inner,opts=m.group(1).strip(),m.group(2),m.group(3) or ''
    parts=split_top_level(inner)
    url=unquote(parts[0]) if parts and parts[0] else None
    if not url:return None,'script URL must be a quoted string',[]
    if len(parts)>2:return None,'script() has too many arguments',[]
    e={'type':'schedule'} if cron else {'type':'http_response' if m.group(1).lower()=='response' else 'http_request'}
    if cron:
        expr=trigger
        pm=re.fullmatch(r'\$\{([^{}]+)\}',expr)
        if pm:
            name=pm.group(1).strip()
            if name not in defaults:return None,'undeclared cron argument '+name,[]
            expr=defaults[name]
        else:
            v=unquote(expr)
            if v is not None:expr=v
        expr,err=quartz_to_cron(expr)
        if err:return None,err,[]
        e['cron']=expr
    else:
        cond=re.sub(r'^\$\{url\}\s*(?:~=|==?)\s*','',trigger)
        if '${' in cond:return None,'match condition uses dynamic arguments',[]
        e['match']=bare_regex(cond)
    if len(parts)==2:
        arg,err=resolve_script_argument(parts[1],defaults)
        if err:return None,err,[]
        if arg:e['arguments']={'_compat.$argument':arg}
    notes=[]
    for opt in split_top_level(opts):
        if not opt:continue
        om=re.match(r'^([A-Za-z_][\w-]*)\s*=\s*(.*)$',opt,re.S)
        if not om:return None,'unrecognized script option '+opt,[]
        key,val=om.group(1).lower(),om.group(2).strip()
        if key=='tag':
            v=unquote(val)
            if v is None:return None,'tag must be a quoted string',[]
            e['name']=v
        elif key=='timeout':
            pm=re.fullmatch(r'\$\{([^{}]+)\}',val)
            if pm:
                name=pm.group(1).strip()
                if name not in defaults:return None,'undeclared timeout argument '+name,[]
                val=defaults[name]
            if not re.fullmatch(r'\d+',val):return None,'timeout is not a number',[]
            e['timeout']=int(val)
        elif key=='requires_body':
            e['body_required']=val.lower()=='true'
        elif key=='binary_body_mode':
            if val.lower()=='true':e['binary_body']=True
        elif key=='enable':
            pm=re.fullmatch(r'\$\{([^{}]+)\}',val)
            if pm:
                name=pm.group(1).strip()
                if name not in defaults:return None,'undeclared enable argument '+name,[]
                val=defaults[name]
            v=unquote(val)
            if v is not None:val=v
            if val.lower() not in ('true','false'):return None,'enable must be true or false',[]
            if val.lower()=='false':e['disabled']=True
        elif key=='img_url':
            notes.append('script option img_url has no Egern equivalent (dropped): '+line)
        else:
            return None,'unsupported script option '+key,[]
    return e,'',notes
def json_directive(directive):
    m=re.fullmatch(r'(response|request)\s*\.\s*json\s*\.\s*(delete|replace|jq|jq_file)\s*\((.*)\)\s*$',directive.strip(),re.I|re.S)
    if not m:return None
    kind,op,arg=m.group(1).lower(),m.group(2).lower(),m.group(3).strip()
    if op in('jq','jq_file'):
        filt=json.loads(arg)
        if not isinstance(filt,str) or not filt.strip():raise ValueError('invalid json.'+op+' argument')
    elif op=='delete':
        val=json.loads(arg)
        items=val if isinstance(val,list) else [val]
        if not items or not all(isinstance(x,str) for x in items):raise ValueError('invalid json.delete argument')
        filt='delpaths('+json.dumps([split_path(x) for x in items],ensure_ascii=False)+')'
    else:
        dec=json.JSONDecoder()
        try:first,idx=dec.raw_decode(arg)
        except Exception:raise ValueError('invalid json.replace argument')
        rest=arg[idx:].lstrip()
        if not rest.startswith(','):raise ValueError('invalid json.replace argument')
        second=rest[1:].strip()
        val=json.loads(second)
        if isinstance(first,list) and all(isinstance(x,str) for x in first):
            if not isinstance(val,list) or len(val)!=len(first):raise ValueError('mismatched json.replace arguments')
            filt=' | '.join('setpath('+json.dumps(split_path(p),ensure_ascii=False)+'; '+json.dumps(v,ensure_ascii=False)+')' for p,v in zip(first,val))
        elif isinstance(first,str):
            filt='setpath('+json.dumps(split_path(first),ensure_ascii=False)+'; '+json.dumps(val,ensure_ascii=False)+')'
        else:raise ValueError('invalid json.replace argument')
    return {'kind':kind+'_jq','filter':filt}
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
    defaults=argument_defaults(sections.get('argument',[]))
    scripts=[]; hosts=[]; rewrites=[]; body_rewrites=[]; issues=[]; rules=[]
    for line in sections.get('rule',[]):
        try:
            parts=split_paren(line)
            if len(parts)<3:raise ValueError('malformed rule')
            policy=parts[-1];flags=[]
            if policy.lower()=='no-resolve':flags=['no-resolve'];parts=parts[:-1];policy=parts[-1]
            pol=policy.upper()
            if pol.startswith('REJECT'):pol='REJECT'
            elif pol!='DIRECT':raise ValueError('unsupported policy '+policy)
            node=rule_node(parts[0],','.join(parts[1:-1]))
            rules.append(rule_lines(node,2,pol,'no-resolve' in flags and node['type'].startswith('ip_cidr')))
        except Exception as exc: issues.append(f'unsupported rule (skipped): {line} ({exc})')
    for line in sections.get('mitm',[]):
        m=re.match(r'hostname\s*=\s*(.*)',line,re.I)
        if m:hosts.extend(x.strip() for x in m.group(1).split(',') if x.strip())
    for line in sections.get('script',[]):
        entry,err,notes=parse_script_line(line,defaults)
        if err:issues.append('unsupported script: '+line+' ('+err+')');continue
        scripts.append(entry);issues.extend(notes)
    reject_map={'reject':'reject','reject_200':'reject-200','reject_dict':'reject-dict','reject_array':'reject-array','reject_img':'reject-img','reject_html':'reject-html','reject_drop':'reject-drop'}
    for line in sections.get('rewrite',[]):
        try:
            m=re.match(r'^(?:request|response)\s+if\s+(.+?)\s+then\s+(.+)$',line.strip(),re.I)
            if m:
                match,directive=m.groups(); match=re.sub(r'^\$\{url\}\s*(?:~=|=)\s*','',match.strip())
            else:
                parts=line.split()
                if len(parts)<2: raise ValueError('missing action')
                match,directive=parts[0],' '.join(parts[1:])
            jd=json_directive(directive)
            if jd:
                jd['match']=bare_regex(match);body_rewrites.append(jd);continue
            call=re.fullmatch(r'([\w-]+)(?:\((.*?)\))?',directive.strip(),re.I)
            if not call: raise ValueError('unknown directive')
            action,arg=call.groups(); normalized=action.lower().replace('-','_')
            if normalized in reject_map: rewrites.append({'match':match,'action':reject_map[normalized]})
            elif action.lower() in ('302','307','redirect'):
                to=arg.strip(' \"\'') if arg else directive.split()[-1].strip(' \"\'')
                rewrites.append({'match':match,'action':'redirect','to':to})
            else: raise ValueError('unsupported action '+action)
        except Exception as exc: issues.append(f'unsupported rewrite (skipped): {line} ({exc})')
    if not scripts and not rewrites and not body_rewrites and not hosts and not rules: raise ValueError('No convertible script, rewrite, or MITM hostname rules')
    lines=[]
    for key,outkey in [('name','name'),('desc','description'),('author','author'),('icon','icon')]:
        if meta.get(key):lines.append(f'{outkey}: {q(meta[key])}')
    if not any(x.startswith('name:') for x in lines):lines.insert(0,'name: '+q(Path(filename).stem))
    if hosts:lines+=['mitm:','  hostnames:']+['    - '+q(x) for x in dict.fromkeys(hosts)]
    if rules:
        lines.append('rules:')
        for r in rules:lines+=r
    if scripts:
        lines.append('scriptings:')
        for e in scripts:
            lines.append('  - '+e['type']+':')
            for k in ('name','match','cron','script_url','timeout','body_required','binary_body','disabled'):
                if k not in e:continue
                v=e[k]
                if isinstance(v,bool):lines.append('      '+k+': '+str(v).lower())
                elif isinstance(v,int):lines.append('      '+k+': '+str(v))
                else:lines.append('      '+k+': '+q(v))
            if e.get('arguments'):
                lines.append('      arguments:')
                for ak,av in e['arguments'].items():
                    lines.append('        '+q(ak)+': '+q(av))
    if rewrites:
        lines+=['http:','  rewrite:']
        for e in rewrites:
            lines+=['    - '+q(e['match'] or 'all')+':']
            if e['action']=='redirect':lines.append('        redirect: '+q(e['to']))
            else:lines.append('        '+e['action']+': true')
    if body_rewrites:
        lines.append('body_rewrites:')
        for e in body_rewrites:
            lines+=['  - '+e['kind']+':','      match: '+q(e['match']),'      filter: '+q(e['filter'])]
    return '\n'.join(lines)+'\n',issues
def main():
    try: listing=json.loads(fetch(API))
    except Exception as exc: print('ERROR unable to fetch upstream listing:',exc);return
    entries=[x for x in listing if x.get('type')=='file' and x.get('name','').lower().endswith('.lpx')]
    if not entries: print('WARNING upstream API returned no .lpx files; retaining existing modules');return
    wanted=load_whitelist()
    if wanted is not None:
        have={Path(x['name']).stem.lower() for x in entries}
        for name in sorted(wanted-have):print('WARNING whitelist entry not found upstream:',name)
        entries=[x for x in entries if Path(x['name']).stem.lower() in wanted]
        print(f'WHITELIST active: {len(wanted)} names, {len(entries)} matched upstream')
        if not entries: print('WARNING no whitelist entries matched; nothing converted');return
    else: print('WHITELIST not set: converting all upstream plugins')
    OUT.mkdir(parents=True,exist_ok=True); done=[]; failed=[]
    for item in sorted(entries,key=lambda x:x['name'].lower()):
        try:
            source=fetch(item.get('download_url') or RAW+item['name']); output,issues=parse(source,item['name'])
            (OUT/(Path(item['name']).stem+'.yaml')).write_text(output,encoding='utf-8')
            done.append(item['name']);print('CONVERTED',item['name'],'warnings='+str(len(issues)))
            for issue in issues:print('WARNING',item['name'],issue)
        except Exception as exc:failed.append((item.get('name','?'),str(exc)));print('FAILED',item.get('name','?'),exc)
    try:
        (ROOT/'scripts'/'egern_lpx_sources.json').write_text(json.dumps([{'name':x['name'],'url':x.get('download_url') or RAW+x['name'],'output':'egern/modules/'+Path(x['name']).stem+'.yaml'} for x in entries],ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    except Exception as exc: print('WARNING unable to write source manifest:',exc)
    print(f'SUMMARY total={len(entries)} converted={len(done)} failed={len(failed)}')
if __name__=='__main__':main()
