import type {Snapshot,Check} from './types';
import {isObservationFresh} from './api';
const now=()=>Date.now();
let snapshotCalls=0;
const scenario=new URLSearchParams(location.search).get("scenario");
let state:Snapshot={version:'0.2.1',os:'macos',coreEpoch:'demo',settings:{revision:1,mode:'hourly',enabled:false,paused:false,patrol:{provider:'none',model:'gpt-6-luna',inputRate:0,outputRate:0},resolver:{provider:'none',model:'gpt-6.1-sol',inputRate:0,outputRate:0}},active:null,runs:[],findings:[],files:[],analyses:[],cloudEnabled:false,credentials:{},catalogs:{},budget:{usedToday:0,reserved:0,used30Days:0,patrolCalls:0,resolverCalls:0,unknown:0},nextDue:null,gap:'デモデータです。PCは検査していません。',watcherStatus:'停止中',analysisCancelRequested:false,catalogInFlight:false,ledgerBlocked:false,response:{policy:{revision:1,mode:'confirm',autoEscalate:false,expiresAt:null},capabilities:[{action:'pause_cloud',available:true,reason:'守護AIのクラウド送信だけを停止します。PC全通信は対象外。'},{action:'quarantine_file',available:false,reason:'ファイル隔離はこの版では未対応です。'},{action:'block_connection',available:false,reason:'接続の遮断はこの版では未対応です。'}],plans:[]}};
const checks:Check[]=[{id:'gatekeeper',title:'Gatekeeper',category:'保護設定',status:'ok',detail:'この保護機能は有効です。',source:'demo fixture',observedAt:now(),digest:null},{id:'firewall',title:'アプリケーションファイアウォール',category:'保護設定',status:'attention',detail:'この保護機能は無効です。OSの設定を確認してください。',source:'demo fixture',observedAt:now(),digest:null},{id:'av_alerts',title:'既存ウイルス対策の警告履歴',category:'既存警告',status:'unavailable',detail:'この版では未対応です。標準セキュリティ画面で確認してください。',source:'demo fixture',observedAt:now(),digest:null}];
if(scenario?.startsWith('response')){state.cloudEnabled=true;state.response.plans=[{id:'fixture-plan',runId:'fixture-run',analysisId:'fixture-analysis',action:'pause_cloud',status:'proposed',reason:'人工データ：対策AIが緊急対応を提案。ローカルの要確認根拠あり。',createdAt:now(),expiresAt:now()+300000,policyRevision:1,evidenceIds:['fixture-attention-1']}];}
if(scenario==='historical-active'){const old=now()-600000;state.runs=[{id:'old-history',trigger:'manual',status:'completed',startedAt:old,finishedAt:old,checks}];state.active={id:'different-live',trigger:'schedule',status:'running',startedAt:now(),finishedAt:null,checks:[]};state.cloudEnabled=true;}
if(scenario==='baseline'){
 const makeRun=(runId:string,digest:string)=>{const observed=now();return {id:runId,trigger:'manual',status:'completed',startedAt:observed,finishedAt:observed,checks:[{...checks[0],id:'fixture-file',title:'人工ファイル',status:'unverified',detail:'比較基準の確認待ち',digest,observedAt:observed}]};};
 state.runs=[makeRun('fixture-a','A')];
 Object.assign(window,{__shugoDemoReplaceBaseline:()=>{state.runs.unshift(makeRun('fixture-b','B'));}});
}
if(scenario==='mutation-race')state.cloudEnabled=true;
if(scenario==='future-observation'){const future=now()+600000;state.runs=[{id:'future',trigger:'manual',status:'completed',startedAt:future,finishedAt:future,checks:checks.map(c=>({...c,observedAt:future}))}];}
export async function demoCommand(name:string,args:Record<string,unknown>):Promise<unknown>{
 if(name==='snapshot'){snapshotCalls++;Object.assign(window,{__shugoDemoSnapshotCalls:snapshotCalls});if(scenario==='hang'&&snapshotCalls>1)return new Promise(()=>{});if(scenario==='disconnect'&&snapshotCalls>2)throw new Error('fixture disconnect');if(scenario==='mutation-race'&&snapshotCalls===2){const old=structuredClone(state);await new Promise(r=>setTimeout(r,1500));return old;}if(scenario==='out-of-order'&&snapshotCalls===1){const old=structuredClone(state);await new Promise(r=>setTimeout(r,1500));return old;}if(scenario==='out-of-order'&&snapshotCalls>1)state.settings.paused=true;return structuredClone(state);}
 if(name==='set_response_policy'){if(scenario==='response-cancel')return 'cancelled';if(args.revision!==state.response.policy.revision)throw new Error('対策設定が更新されました');state.response.policy={revision:state.response.policy.revision+1,mode:args.mode as 'confirm'|'automatic',autoEscalate:!!args.autoEscalate,expiresAt:now()+3600000};return 'applied';}
 if(name==='revoke_response_policy'){state.response.policy={revision:state.response.policy.revision+1,mode:'confirm',autoEscalate:false,expiresAt:null};return 'applied';}
 if(name==='execute_response'){if(scenario==='response-cancel')return 'cancelled';const plan=state.response.plans.find(p=>p.id===args.planId);if(!plan||plan.status!=='proposed'||plan.expiresAt<now()||plan.policyRevision!==state.response.policy.revision||args.revision!==state.response.policy.revision)throw new Error('提案は実行できません');plan.status='executed';state.cloudEnabled=false;return 'applied';}
 if(name==='emergency_lock'){state.cloudEnabled=false;state.credentials={};state.response.policy={revision:state.response.policy.revision+1,mode:'confirm',autoEscalate:false,expiresAt:null};return 'applied';}
 if(name==='export_report')return 'cancelled';
 if(name==='scan_start'){
  if(state.settings.paused)throw new Error('一時停止中です');
  if(state.active)return state.active.id;
  const id=crypto.randomUUID();state.active={id,trigger:'manual',status:'running',startedAt:now(),finishedAt:null,checks:[]};
  setTimeout(()=>{if(state.active?.id!==id)return;const run={...state.active,status:'partial',finishedAt:now(),checks};state.runs.unshift(run);state.active=null;state.findings=[{id:'f1',checkId:'firewall',title:checks[1].title,detail:checks[1].detail,status:'open',firstSeen:now(),lastSeen:now()}];},700);return id;
 }
 if(name==='scan_cancel'){if(state.active){state.runs.unshift({...state.active,status:'cancelled',finishedAt:now()});state.active=null;}return;}
 if(name==='set_paused'){state.settings.paused=!!args.paused;state.settings.revision++;if(args.paused)state.active=null;return;}
 if(name==='set_schedule'){state.settings.mode=args.mode as string;state.settings.enabled=!!args.enabled && args.mode!=='manual';state.settings.revision++;state.nextDue=state.settings.enabled?now()+3600000:null;return;}
 if(name==='set_models'){if(scenario==='model-save-race')await new Promise(r=>setTimeout(r,800));state.settings.patrol=args.patrol as Snapshot['settings']['patrol'];state.settings.resolver=args.resolver as Snapshot['settings']['resolver'];state.settings.revision++;state.cloudEnabled=false;state.response.policy={revision:state.response.policy.revision+1,mode:'confirm',autoEscalate:false,expiresAt:null};return;}
 if(name==='accept_baseline'){const run=state.runs[0],check=run?.checks.find(c=>c.id===args.checkId);if(state.active||state.settings.paused||run?.id!==args.runId||!check?.digest||check.digest!==args.digest||check.observedAt!==args.observedAt||!isObservationFresh(check.observedAt))throw new Error('選択した観測が古いか変更されています');Object.assign(window,{__shugoDemoBaseline:args});return 'applied';}
 if(name==='acknowledge'){state.findings.forEach(f=>f.status='acknowledged');return;}
 if(name==='cloud_disable'){state.cloudEnabled=false;return;}
 throw new Error('この操作はデスクトップアプリで利用できます。');
}
