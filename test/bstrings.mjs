import { StringScanner, searchStrings, BUILTIN } from '../js/core/bsearch.js';
const enc=new TextEncoder();
const parts=[]; const u16=(s)=>{const b=new Uint8Array(s.length*2); for(let i=0;i<s.length;i++) b[i*2]=s.charCodeAt(i); return b;};
parts.push(new Uint8Array([0,1,2]), enc.encode('hello world ascii'), new Uint8Array([0xff]), u16('unicode string here'), new Uint8Array([0xfe,0x00,0x01]), u16('odd aligned flag{s0me_fl4g}'), new Uint8Array([5]), enc.encode('192.168.10.5 and http://evil.example/x'), new Uint8Array([0]), enc.encode('123456-123456-123456-123456-123456-123456-123456-123456'), new Uint8Array([0,0]));
let tot=0; for(const p of parts) tot+=p.length; const buf=new Uint8Array(tot); let o=0; for(const p of parts){buf.set(p,o);o+=p.length;}
const run=(chunk)=>{const out=[]; const sc=new StringScanner({min:4},(s,off,e)=>out.push(`${e}@${off}:${s}`)); for(let i=0;i<buf.length;i+=chunk) sc.feed(buf.subarray(i,i+chunk),i); sc.end(); return out.sort().join('\n');};
const ref=run(1e9); console.log(ref);
for (const c of [1,2,3,5,7,64]) console.log('chunk',c, run(c)===ref ? 'same':'DIFF\n'+run(c));
for (const r of Object.keys(BUILTIN)) new RegExp(BUILTIN[r][1],'gi');
const res=await searchStrings([{name:'t.bin',data:buf}],{mode:'builtin',patterns:['ipv4','flag','bitlocker','url3986','email'],onlyMatch:true,min:4});
console.log(res.rows);
const res2=await searchStrings([{name:'t.bin',data:buf}],{mode:'text',query:'FLAG',min:4}); console.log(res2.rows);
let fail = 0;
for (const c of [1, 2, 3, 5, 7, 64]) if (run(c) !== ref) { console.log('FAIL chunk', c); fail++; }
if (!res.rows.some((r) => r[4] === 'flag{s0me_fl4g}' && r[2] === 'U')) { console.log('FAIL unicode flag'); fail++; }
if (!res.rows.some((r) => r[5] === 'bitlocker')) { console.log('FAIL bitlocker'); fail++; }
console.log(fail ? `${fail} failure(s)` : 'bstrings scanner checks passed');
process.exit(fail ? 1 : 0);
