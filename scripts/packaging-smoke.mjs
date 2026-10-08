// Packaging only: no scan, API, installation, privilege change or release.
import {statSync,readdirSync,readFileSync} from 'node:fs';
import {resolve,join} from 'node:path';
import {spawnSync} from 'node:child_process';
const [mode, arg, dir] = process.argv.slice(2);
if(mode==='cli') {
 const binary=resolve(arg); if(!statSync(binary).isFile()) throw Error('CLI binary missing');
 const child=spawnSync(binary,['--help'],{shell:false,encoding:'utf8',timeout:10000,maxBuffer:65536});
 if(child.error||child.status!==0||!child.stdout.trim()) throw Error('CLI help smoke failed');
 console.log('CLI help succeeded; no monitoring or network was started');
} else if(mode==='bundle') {
 const expected={macos:['.app','.dmg'],windows:['.exe'],linux:['.deb','.rpm','.AppImage']}[arg];
 if(!expected||!dir) throw Error('Unknown bundle platform');
 const found=[]; function walk(p){for(const e of readdirSync(p,{withFileTypes:true})){const q=join(p,e.name);if(e.name.endsWith('.app')&&e.isDirectory())found.push(q);else if(e.isDirectory())walk(q);else if(e.isFile()&&statSync(q).size>0)found.push(q);}}
 walk(resolve(dir));for(const ext of expected)if(!found.some(p=>p.endsWith(ext)))throw Error(`Missing ${ext} bundle`);
 console.log('Bundle formats present; install/runtime/signing NOT verified');
} else if(mode==='config') {
 const expected={macos:['app','dmg'],windows:['nsis'],linux:['deb','rpm','appimage']};
 const base=JSON.parse(readFileSync('src-tauri/tauri.conf.json','utf8'));
 if(base.bundle.targets!=='all')throw Error('Portable base targets required');
 for(const [os,targets] of Object.entries(expected)){
  const config=JSON.parse(readFileSync(`src-tauri/tauri.${os}.conf.json`,'utf8'));
  if(JSON.stringify(config.bundle.targets)!==JSON.stringify(targets))throw Error('OS targets mismatch');
  if(config.app||config.build)throw Error('Platform config must preserve UI/security/build');
 }
 console.log('OS config matrix valid');
} else throw Error('Usage: packaging-smoke.mjs config | cli <binary> | bundle <os> <directory>');
