import {test,expect} from '@playwright/test';
test.beforeEach(async({page})=>{await page.goto('/?demo=1');await expect(page.getByRole('button',{name:'巡回実施',exact:true})).toBeVisible()});
test('scan, partial result, unresolved acknowledgement and history',async({page})=>{
 await page.getByRole('button',{name:'巡回実施',exact:true}).click();
 await expect(page.getByRole('button',{name:'検査しています…',exact:true})).toBeDisabled();
 await expect(page.getByText('一部の項目は未検査です')).toBeVisible();
 await expect(page.getByText('既存ウイルス対策の警告履歴',{exact:true})).toBeVisible();
 await page.getByRole('button',{name:'確認しました',exact:true}).click();
 await expect(page.getByRole('button',{name:'確認済み・未解決'})).toBeVisible();
 await page.getByRole('button',{name:'巡回の履歴',exact:true}).click();
 await expect(page.getByRole('button',{name:/手動巡回/})).toBeVisible();
});
test('pause blocks scan; manual mode cannot enable schedule',async({page})=>{
 await page.getByRole('button',{name:'すべて一時停止'}).click();
 await expect(page.getByRole('button',{name:'巡回実施',exact:true})).toBeDisabled();
 await page.getByRole('button',{name:'再開する'}).click();
 await expect(page.getByRole('button',{name:'巡回実施',exact:true})).toBeEnabled();
 await page.getByLabel('巡回間隔').selectOption('manual');
 await expect(page.getByRole('checkbox',{name:'自動巡回 OFF'})).toBeDisabled();
});
test('model roles independent; CLI limitations visible',async({page})=>{
 await page.getByLabel('巡回の接続先').selectOption('codex');
 await page.getByLabel('対策の接続先').selectOption('claude_code');
 await page.getByRole('button',{name:'モデル選択を保存'}).click();
 await expect(page.getByLabel('巡回の接続先')).toHaveValue('codex');
 await expect(page.getByLabel('対策の接続先')).toHaveValue('claude_code');
 await expect(page.getByText('CLIはこの版では実行しません。API接続を利用できます。')).toHaveCount(2);
});
test('fact detail renders inert text and can close using keyboard',async({page})=>{
 await page.getByRole('button',{name:'巡回実施',exact:true}).click();
 await page.getByRole('button',{name:/Gatekeeper この保護/}).click();
 await expect(page.getByRole('dialog')).toBeVisible();
 await page.getByRole('button',{name:'詳細を閉じる'}).press('Enter');
 await expect(page.getByRole('dialog')).toHaveCount(0);
});
test('compact viewport preserves primary controls and no horizontal overflow',async({page})=>{
 await page.setViewportSize({width:640,height:900});
 await expect(page.getByRole('button',{name:'巡回実施',exact:true})).toBeVisible();
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBeTruthy();
 await page.screenshot({path:'test-results/dashboard-demo.png',fullPage:true});
});
test('unsaved model draft survives schedule change',async({page})=>{await page.getByLabel('巡回の接続先').selectOption('codex');await page.getByLabel('巡回間隔').selectOption('quarter');await expect(page.getByLabel('巡回の接続先')).toHaveValue('codex');await expect(page.getByText('モデル選択は未保存')).toBeVisible();});
test('modal traps focus, Escape restores trigger, compact navigation named',async({page})=>{await page.getByRole('button',{name:'巡回実施',exact:true}).click();const trigger=page.getByRole('button',{name:/Gatekeeper この保護/});await trigger.click();await page.keyboard.press('Shift+Tab');await expect(page.getByRole('button',{name:'閉じる',exact:true})).toBeFocused();await page.keyboard.press('Escape');await expect(trigger).toBeFocused();await page.setViewportSize({width:640,height:900});await expect(page.getByRole('button',{name:'AI接続と費用',exact:true})).toBeVisible();});
test('engine disconnect invalidates old status and start',async({page})=>{await page.goto('/?demo=1&scenario=disconnect');await expect(page.getByText(/巡回エンジンとの接続が切れています/)).toBeVisible({timeout:6000});await expect(page.getByRole('button',{name:'巡回実施',exact:true})).toBeDisabled();});
test('out of order snapshots cannot restore stale active state',async({page})=>{await page.goto('/?demo=1&scenario=out-of-order');await expect(page.getByRole('button',{name:'再開する'})).toBeVisible();await expect(page.getByRole('button',{name:'巡回実施',exact:true})).toBeDisabled();await expect.poll(async()=>page.getByRole('button',{name:'再開する'}).count(),{timeout:2500}).toBe(1);});
test('native cancel outcome is not a success claim',async({page})=>{await page.getByRole('button',{name:'巡回実施',exact:true}).click();await expect(page.getByText('一部の項目は未検査です')).toBeVisible();await page.getByRole('button',{name:'巡回の履歴',exact:true}).click();await page.getByRole('button',{name:'JSON保存'}).click();await expect(page.getByText('操作を取り消しました。変更していません。')).toBeVisible();await expect(page.getByText('レポート保存の操作が完了しました')).toHaveCount(0);});

test('hung snapshot times out without accumulating IPC requests',async({page})=>{await page.goto('/?demo=1&scenario=hang');await expect(page.getByText(/巡回エンジンの応答が期限を超えました/)).toBeVisible({timeout:9000});await expect(page.getByRole('button',{name:'巡回実施',exact:true})).toBeDisabled();await expect.poll(()=>page.evaluate(()=>(window as unknown as {__shugoDemoSnapshotCalls:number}).__shugoDemoSnapshotCalls)).toBe(2);await page.waitForTimeout(1200);expect(await page.evaluate(()=>(window as unknown as {__shugoDemoSnapshotCalls:number}).__shugoDemoSnapshotCalls)).toBe(2);});
test('historical results remain historical during a separate live scan',async({page})=>{await page.goto('/?demo=1&scenario=historical-active');await page.getByRole('button',{name:'巡回の履歴',exact:true}).click();await page.getByRole('button',{name:/手動巡回/}).click();await expect(page.getByText('過去の検査結果です。現在の状態は再巡回で確認してください。')).toBeVisible();await expect(page.getByText('PC内の検査完了',{exact:true})).toBeVisible();await expect(page.getByRole('button',{name:'AIで対策を検討'})).toBeDisabled();await expect(page.getByRole('button',{name:'AIで対策を検討'})).toHaveAttribute('title','古い検査結果です。再巡回してください');await expect(page.getByText('Gatekeeper',{exact:true})).toBeVisible();});

test('disabled refinement exposes a visible reason and safe settings navigation',async({page})=>{await page.setViewportSize({width:640,height:900});await page.getByRole('button',{name:'巡回実施',exact:true}).click();await expect(page.getByText('一部の項目は未検査です')).toBeVisible();const button=page.getByRole('button',{name:'AIで対策を検討'});await expect(button).toBeDisabled();await expect(button).toHaveAttribute('aria-describedby','refine-reason');await expect(page.locator('#refine-reason')).toContainText('AI接続と費用から送信を許可してください');await page.locator('#refine-reason').getByRole('button',{name:'AI接続と費用へ'}).focus();await page.keyboard.press('Enter');await expect(page.getByRole('heading',{name:'API接続',exact:true})).toBeVisible();await expect(page.getByRole('button',{name:'送信内容を確認して許可'})).toBeVisible();});

test('response defaults to confirmation and unsupported operations stay unavailable',async({page})=>{await expect(page.getByLabel('操作の確認方法')).toHaveValue('confirm');await expect(page.getByRole('checkbox',{name:'巡回から対策モデルへ自動で引き継ぐ'})).not.toBeChecked();await expect(page.getByText('ファイル隔離はこの版では未対応です。')).toBeVisible();await expect(page.getByText('接続の遮断はこの版では未対応です。')).toBeVisible();await page.getByLabel('操作の確認方法').selectOption('automatic');await expect(page.getByText(/許可期限：/)).toBeVisible();await expect(page.getByRole('checkbox',{name:'巡回から対策モデルへ自動で引き継ぐ'})).not.toBeChecked();});
test('response native cancellation never enables automatic policy or executes a plan',async({page})=>{await page.goto('/?demo=1&scenario=response-cancel');await page.getByLabel('操作の確認方法').selectOption('automatic');await expect(page.getByLabel('操作の確認方法')).toHaveValue('confirm');await page.getByRole('button',{name:'内容を確認して実行'}).click();await expect(page.getByText('操作を取り消しました。変更していません。')).toBeVisible();await expect(page.getByText('クラウド許可中',{exact:true})).toBeVisible();await expect(page.getByRole('button',{name:'内容を確認して実行'})).toBeEnabled();});
test('response plan is single use; emergency lock states its limited scope',async({page})=>{await page.goto('/?demo=1&scenario=response-plan');await page.getByRole('button',{name:'内容を確認して実行'}).click();await expect(page.getByRole('button',{name:'内容を確認して実行'})).toBeDisabled();await expect(page.getByText('この提案は再実行しません')).toBeVisible();await page.getByRole('button',{name:'緊急：新規クラウド解析送信を停止'}).click();await expect(page.getByText('クラウド送信 OFF',{exact:true})).toBeVisible();await expect(page.getByText(/PC全体のネットワーク遮断や/)).toBeVisible();await page.getByRole('button',{name:'停止後の戻し方を見る'}).click();await expect(page.getByText(/許可や通信は自動で再開しません/)).toBeVisible();});

test('baseline approval remains bound to the observation displayed in detail',async({page})=>{
 await page.goto('/?demo=1&scenario=baseline');
 await page.getByRole('button',{name:/人工ファイル 比較基準/}).click();
 await expect(page.getByRole('button',{name:'確認して比較基準にする'})).toBeEnabled();
 await page.evaluate(()=>(window as unknown as {__shugoDemoReplaceBaseline:()=>void}).__shugoDemoReplaceBaseline());
 await expect(page.getByRole('button',{name:'確認して比較基準にする'})).toBeDisabled();
 await expect(page.getByText(/選択した観測が古いか状態未確認/)).toBeVisible();
 expect(await page.evaluate(()=>(window as unknown as {__shugoDemoBaseline?:unknown}).__shugoDemoBaseline)).toBeUndefined();
 await page.getByRole('button',{name:'詳細を閉じる'}).click();
 await page.getByRole('button',{name:/人工ファイル 比較基準/}).click();
 await page.getByRole('button',{name:'確認して比較基準にする'}).click();
 await expect.poll(()=>page.evaluate(()=>(window as unknown as {__shugoDemoBaseline:{runId:string;digest:string}}).__shugoDemoBaseline)).toMatchObject({runId:'fixture-b',digest:'B'});
});
test('snapshot captured before cloud stop cannot restore the old ON display',async({page})=>{
 await page.goto('/?demo=1&scenario=mutation-race');
 await expect(page.getByText('クラウド許可中',{exact:true})).toBeVisible();
 await expect.poll(()=>page.evaluate(()=>(window as unknown as {__shugoDemoSnapshotCalls:number}).__shugoDemoSnapshotCalls)).toBe(2);
 await page.getByRole('button',{name:'送信を停止',exact:true}).click();
 await expect(page.getByText('クラウド状態 未確認',{exact:true})).toBeVisible();
 await expect(page.getByText('クラウド送信 OFF',{exact:true})).toBeVisible();
 await page.waitForTimeout(1200);
 await expect(page.getByText('クラウド許可中',{exact:true})).toHaveCount(0);
});
test('model edits made during a pending save remain unsaved instead of being discarded',async({page})=>{
 await page.goto('/?demo=1&scenario=model-save-race');
 await page.getByLabel('巡回の接続先').selectOption('codex');
 await page.getByRole('button',{name:'モデル選択を保存',exact:true}).click();
 await page.getByLabel('巡回の接続先').selectOption('claude_code');
 await expect(page.getByRole('button',{name:'モデル選択を保存',exact:true})).toBeEnabled();
 await expect(page.getByLabel('巡回の接続先')).toHaveValue('claude_code');
 await expect(page.getByText('モデル選択は未保存')).toBeVisible();
});
test('an emergency completion does not clear another pending model save',async({page})=>{
 await page.goto('/?demo=1&scenario=model-save-race');
 await page.getByLabel('巡回の接続先').selectOption('codex');
 await page.getByRole('button',{name:'モデル選択を保存',exact:true}).click();
 await page.getByRole('button',{name:'緊急：新規クラウド解析送信を停止'}).click();
 await expect(page.getByText(/新規クラウド解析送信の停止と、アプリ内の保管APIキーの破棄を要求/)).toBeVisible();
 await expect(page.getByRole('button',{name:'モデル選択を保存',exact:true})).toBeDisabled();
 await expect(page.getByRole('button',{name:'モデル選択を保存',exact:true})).toBeEnabled();
});
test('future observations and disconnected cloud snapshots do not claim a current safe state',async({page})=>{
 await page.goto('/?demo=1&scenario=future-observation');
 await expect(page.locator('.stats > div').nth(1).locator('strong')).toContainText('—');
 await expect(page.getByText('過去の検査結果です。現在の状態は再巡回で確認してください。')).toBeVisible();
 await page.goto('/?demo=1&scenario=disconnect');
 await expect(page.getByText(/巡回エンジンとの接続が切れています/)).toBeVisible();
 await expect(page.getByText('クラウド状態 未確認',{exact:true})).toBeVisible();
 await expect(page.getByText('クラウド送信 OFF',{exact:true})).toHaveCount(0);
 await expect(page.getByText('対策許可 状態未確認',{exact:true})).toBeVisible();
});
