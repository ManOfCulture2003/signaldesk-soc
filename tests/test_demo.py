"""Exercise the actual shipped browser adapter without a backend."""
import shutil
import subprocess
from pathlib import Path
import pytest


def test_browser_demo_decisions_search_and_isolation():
    node=shutil.which('node')
    if not node:
        pytest.skip('Node is needed for browser-demo logic tests')
    root=Path(__file__).resolve().parents[1]
    result=subprocess.run([node,'-e',r'''
const fs=require('fs'),vm=require('vm'),assert=require('assert');
function create(){const state=new Map();const c={window:{},URL,document:{querySelector:()=>({textContent:''})},sessionStorage:{getItem:k=>state.get(k)||null,setItem:(k,v)=>state.set(k,v),removeItem:k=>state.delete(k)}};vm.createContext(c);for(const f of ['demo/seed.js','demo/demo.js'])vm.runInContext(fs.readFileSync(f,'utf8'),c);return c.window;}
(async()=>{const a=create(),b=create();assert.equal((await a.demoApi('/api/stats')).events,16);const rows=await a.demoApi('/api/alerts');assert.equal(rows.length,5);const id=rows[0].id;
await assert.rejects(()=>a.demoApi('/api/alerts/'+id+'/triage',{body:JSON.stringify({version:1,status:'closed',owner:'',note:' ',disposition:'true_positive'})}));
await a.demoApi('/api/alerts/'+id+'/triage',{body:JSON.stringify({version:1,status:'closed',owner:'Reviewer',note:'Known synthetic test',disposition:'benign_positive'})});
assert.equal((await a.demoApi('/api/alerts/'+id)).alert.status,'closed');assert.equal((await b.demoApi('/api/alerts/'+id)).alert.status,'new');
assert.equal((await a.demoApi('/api/events?host=missing')).total,0);assert.equal((await a.demoApi('/api/detect')).created,0);a.resetDemo();assert.equal((await a.demoApi('/api/alerts/'+id)).alert.status,'new');
})().catch(e=>{console.error(e);process.exit(1)});
'''],cwd=root,capture_output=True,text=True)
    assert result.returncode == 0, result.stderr
