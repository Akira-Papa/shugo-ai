import {useState} from 'react';
import {ShieldCheck,CloudOff,Info,LockKeyhole} from 'lucide-react';
import type {Snapshot} from './types';
const actionNames:Record<string,string>={pause_cloud:'守護AIのクラウド送信を停止',quarantine_file:'ファイル隔離',block_connection:'接続の遮断'};
const statusNames:Record<string,string>={proposed:'確認待ち',awaiting_approval:'確認待ち',executing:'実行中',executed:'実行済み',succeeded:'実行済み',blocked:'実行保留',expired:'期限切れ',cancelled:'取消し済み',failed:'実行失敗',unsupported:'未対応',revoked:'許可撤回済み',interrupted:'中断'};
type Props={data:Snapshot;connected:boolean;pending:boolean;act:(name:string,args?:Record<string,unknown>,message?:string)=>Promise<void>};
export default function ResponsePanel({data,connected,pending,act}:Props){
 const response=data.response;const [recovery,setRecovery]=useState(false);
 if(!response)return <section className="section padded"><h2>対策の設定</h2><p>対策エンジンの状態を確認できません。新規対策を実行しません。</p></section>;
 const {policy,capabilities,plans}=response;
 const expired=policy.mode==='automatic'&&(!policy.expiresAt||policy.expiresAt<=Date.now());
 const activeAuto=policy.mode==='automatic'&&!expired;
 const unavailable=pending||!connected||data.settings.paused;
 return <section className="section response-panel"><div className="section-heading"><h2><ShieldCheck size={17}/> 対策の方針</h2><span className="tiny-tag">{!connected?'対策許可 状態未確認':activeAuto?'事前許可の範囲だけ自動':expired?'事前許可は期限切れ':'毎回確認'}</span></div>
 <div className="padded response-body"><p className="small">対策モデルは原因確認と提案を担当します。実行できる操作は、本人が許可した固定の範囲に限ります。</p>
 <div className="response-settings"><label htmlFor="response-mode">操作の確認方法</label><select id="response-mode" value={policy.mode} disabled={unavailable} onChange={e=>void act('set_response_policy',{mode:e.target.value,autoEscalate:policy.autoEscalate,revision:policy.revision})}><option value="confirm">毎回確認（既定）</option><option value="automatic">事前許可の範囲だけ自動</option></select>
 <label className="toggle-label"><input type="checkbox" checked={policy.autoEscalate} disabled={unavailable} onChange={e=>void act('set_response_policy',{mode:policy.mode,autoEscalate:e.target.checked,revision:policy.revision})}/><span>巡回から対策モデルへ自動で引き継ぐ</span></label></div>
 <p className="small">自動引継ぎはAI解析です。操作の自動許可とは別で、送信許可・回数・予算の範囲内で行います。</p>
 <div className="response-contract"><LockKeyhole size={17}/><div><strong>事前許可できる操作：守護AIのクラウド送信停止のみ</strong><p>最大1時間。対策AIの緊急推定と、現在の「要確認」の観測根拠が揃ったときだけ対象にします。AIの判断だけでPCを変更しません。</p>{policy.expiresAt&&<p>許可期限：{new Date(policy.expiresAt).toLocaleString('ja-JP')}{expired?'（期限切れ）':''}</p>}</div></div>
 <div className="response-capabilities">{capabilities.map(c=><div key={c.action}><span className="tiny-tag">{c.available?'この版で対応':'未対応'}</span><strong>{actionNames[c.action]||c.action}</strong><p>{c.reason}</p></div>)}</div>
 <div className="connection-actions"><button className="small-button" disabled={!connected||pending} onClick={()=>void act('revoke_response_policy')}>事前許可・自動引継ぎを解除</button><button className="small-button danger" onClick={()=>void act('emergency_lock',{},'新規クラウド解析送信の停止と、アプリ内の保管APIキーの破棄を要求しました。')}>緊急：新規クラウド解析送信を停止</button></div>
 <p className="small">緊急停止は守護AIの新規クラウド解析送信と、アプリ内で保管しているAPIキーだけが対象です。元のキーファイルや送信中の処理が持つコピーは対象外です。PC全体のネットワーク遮断や、他のアプリの停止は行いません。接続不明時は停止確認も未確認です。送信済みの情報・費用は取り戻せません。</p>
 {plans.length>0&&<div className="response-plans"><h3>固定操作の提案と結果</h3>{plans.slice(0,10).map(plan=>{const cap=capabilities.find(c=>c.action===plan.action);const fresh=plan.expiresAt>Date.now()&&plan.policyRevision===policy.revision;const canExecute=['proposed','awaiting_approval'].includes(plan.status)&&fresh&&cap?.available;return <article className="response-plan" key={plan.id}><div><strong>{actionNames[plan.action]||plan.action}</strong><span className="tiny-tag">{statusNames[plan.status]||plan.status}</span></div><p>{plan.reason}</p><p className="small">根拠ID：{plan.evidenceIds.join('、')||'なし'} · 検査 {plan.runId.slice(0,8)}<br/>提案 {new Date(plan.createdAt).toLocaleString('ja-JP')} ／ 期限 {new Date(plan.expiresAt).toLocaleString('ja-JP')}</p><button className="small-button" disabled={unavailable||!canExecute} aria-describedby={`plan-reason-${plan.id}`} onClick={()=>void act('execute_response',{planId:plan.id,revision:policy.revision})}>内容を確認して実行</button><p id={`plan-reason-${plan.id}`} className="small">{!cap?.available?cap?.reason||'未対応の操作です':!fresh?'期限・設定が変わりました。新しい根拠から確認してください':!['proposed','awaiting_approval'].includes(plan.status)?'この提案は再実行しません': '固定の確認画面で対象と影響を確認します。'}</p></article>})}</div>}
 <button className="text-button" aria-expanded={recovery} onClick={()=>setRecovery(!recovery)}><Info size={14}/>停止後の戻し方を見る</button>{recovery&&<p className="small">クラウド停止の復旧：観測根拠と送信内容を確認し「AI接続と費用」で改めて許可してください。緊急停止でキーを破棄した場合は、本人がキーファイルを再選択します。許可や通信は自動で再開しません。乗っ取りが疑われる場合は別の安全な端末から公式の支援窓口・アカウント状態を確認してください。</p>}
 </div></section>;
}
