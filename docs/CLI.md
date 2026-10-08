# Shugo CLI / VPS監視（v0.3.0 alpha）

GUIを必要としない読み取りCLIです。既存のCore・費用台帳・観測履歴を利用します。マルウェア検知や侵入防止の保証はありません。OS全体の通信遮断・隔離・root shell・自動daemon導入は実装していません。

## ビルドと起動

```sh
cd src-tauri
cargo build --release --no-default-features --bin shugo
./target/release/shugo --help
./target/release/shugo --version
```

既定保存先はGUIから分離した専用 `shugo-cli` ディレクトリです。

| OS | 既定CLI保存先 |
|---|---|
| macOS | `~/Library/Application Support/shugo-cli` |
| Linux | `$XDG_STATE_HOME/shugo-cli`、未設定時 `~/.local/state/shugo-cli` |
| Windows | `%LOCALAPPDATA%\shugo-cli` |

`--data-dir /absolute/dedicated/path` で変更できます。既存Unixディレクトリは本人所有・0700を要求し、シンボリックリンクを拒否します。Windowsは再解析ポイントを拒否しますが、ACLによる同一ユーザー/管理者からの改竄防止を保証しません。ディレクトリの親やユーザー環境が信頼される前提です。同一保存先のGUI/CLI同時起動をロックで拒否します。データの再初期化は費用台帳を失うため、AIの請求上限保証として利用できません。

## 観測と履歴

```sh
shugo scan
shugo --json scan
shugo --json status
shugo --json history
shugo --json watch --interval 60 --count 10
shugo --json watch --interval 60 --connections --access-log /absolute/path/access.log
shugo connections
shugo access-log /absolute/path/access.log
```

watchはフォアグラウンド動作です。count省略時はCtrlC/SIGTERMまで継続し、1回の完了後にinterval秒待ちます（1〜86400秒）。通常schedulerを起動せず、このCLIでAIの定期送信を行いません。CtrlC/SIGTERMは新しい観測を止め、進行中の観測/解析へ取消しを要求し、保存完了を待ちます。強制終了は次回起動で未完了記録を回復します。送信済みのAPI要求・情報・料金は取り消せません。

既定scan/watch表示は観測時刻・検査status/title/detail・未知範囲を示す人向け要約です。--jsonではscanを従来のRun形式でJSON出力し、watchは1観測1行のNDJSONです。watch --connections / --access-log PATHを指定すると `{run, connections, accessLog, coverage}` 形式になります。追加レポートは各自の観測時刻を持ち、TCP/logはSQLiteのRun履歴へ保存しません。ログ失敗もwatchは継続し、accessLog.error、status unavailable、coverage partialを表示します。coverage observedも侵入なし/安全の保証ではありません。エラーはstderrのJSONとexit 1になります。チェックの `unavailable` やrunの `partial` は未検査/不完全です。`ok` はその観測条件に一致しただけです。空の通信一覧は侵入なしの証明になりません。connectionsのstatusはobserved/partial/unavailableを保持します。単発connectionsは取得不能レポートをstdoutへ出力した上でstderr説明・exit 1を返します。partialはexit 0ですが欠測を含むため、機械利用時は必ずstatusを確認してください。watchは部分的失敗でも継続しcoverageを表示します。

アクセスログは本人指定の通常ファイルを上限付きで読みます。Apache/nginx系の先頭IPを集計し、リクエストパス・query・User-Agent・生行を出力/AI送信しません。IPを観測できても攻撃者/通信方向/感染を断定しません。権限不足やログ不存在はexit 1です。

## ファイルと基準

```sh
shugo files add /absolute/path/config.txt
shugo --json scan
shugo baseline --check-id FILE_CHECK_ID --run-id RUN_ID \
  --digest OBSERVED_DIGEST --observed-at OBSERVED_TIMESTAMP_MS --yes
```

通常ファイル16MiB以下、登録100件まで。ファイルは実行しません。観測内容を本人が確認した後、scanの同じrun/check/digest/observedAtを指定します。最新の完了観測、5分以内、時刻/ハッシュ一致を要求し、取り違え・古い観測・未来時刻を拒否します。`--yes`は比較基準登録への明示承認であり、内容の安全認定ではありません。

## モデルと一回のAI解析

```sh
shugo models
shugo models set --role patrol --provider openai --model MODEL_ID \
  --input-rate 1000000 --output-rate 5000000
shugo ai --role patrol --provider openai --model MODEL_ID \
  --input-rate 1000000 --output-rate 5000000 \
  --key-file /absolute/private/key-file --allow-cloud
```

`--role patrol|resolver`。対応APIはopenai/anthropic、models setはnoneも選択可能です。モデルIDと単価は利用先の現在の公式仕様を確認して設定してください。特定のluna/sol/astra名がAPI上で利用可能だとは保証しません。

単価は**整数microUSD / 百万token**。1000000 = USD 1.00 / 百万token。CLI helpにも単位を表示します。キーは引数値や環境変数で受けず、本人指定のファイルを読み、メモリだけに保持します。Unixでは本人所有・0600相当（group/other許可なし）・hardlinkなしを要求します。末尾改行は取り除きます。キーそのものは出力しません。

aiは巡回結果を作りません。先にscanを実行し、最新5分以内の結果を使います。毎回 `--allow-cloud` が必要です。指定モデルを設定保存した後、公式APIへ**モデル一覧取得1回と解析1回**を行います（一覧取得はPC観測を送信しません）。解析送信はOS種別・検査カテゴリ・状態・根拠の連番だけで、ファイル名/パス/内容/生ログは含みません。GUIと同じ費用予約・使用量の精算・未確定費用停止を利用します。日次USD0.25/30日USD5.00等は設定単価による台帳上の制限であり、実請求上限の保証ではありません。

CLIで自動引継ぎ/自動対策の許可を付与しません。resolverは提案を記録しますが、OS隔離や全通信遮断を実行しません。コマンド終了時にShugoの送信許可とメモリキーを破棄し、次回起動へ復活させません。成功終了は解析succeededかつ費用settledだけです。未確定費用や保存失敗ではクラウドを停止します。CtrlC直前に送信が始まる小さな競合窓や進行中通信の撤回保証はありません。

## 検証境界

CLIの人工fixture integration testで、help/version、許可欠落時のキー未読取、モデル保存、ファイル重複、基準の観測識別、有限watch、追加レポート/欠測coverage、Unix SIGINT/SIGTERMの正常終了・保存・ロック解放、危険保存先、排他、アクセスログの秘密query非出力を確認します。本人の秘密や実APIを使用していません。3OSのCIビルドと各OS実機動作・署名済みインストールの確認は別項目です。パッケージを作っただけで3OSの安全性合格とはしません。

## VPSでの継続利用

まず一般ユーザーで `shugo scan` と `shugo connections` を実行し、検査範囲と未取得項目を確認します。LinuxのTCP観測には `ss`（通常iproute2パッケージ）が必要です。アクセスログは指定ユーザーが読めるファイルだけを選び、読めないことを理由に守護AI全体をrootで常駐させないでください。

`watch`は端末接続が切れると終了することがあります。継続運転は管理者が既存のサービス管理へ登録してください。systemdの**ユーザーサービス**例（パスは設置先へ変更）:

```ini
[Unit]
Description=Shugo local security observations

[Service]
Type=simple
ExecStart=%h/.local/bin/shugo --json watch --interval 900 --connections
Restart=on-failure
RestartSec=30
NoNewPrivileges=true
UMask=0077

[Install]
WantedBy=default.target
```

本アプリはサービス登録・ユーザー追加・linger設定変更を自動実行しません。ユーザーサービスの起動維持はそのサーバーのログイン/linger設定によります。stdoutには接続IPが含まれるため、journal/転送先/ログ保存期間の閲覧権限も管理してください。ログの集計は末尾のスナップショットで、次回も同じ行を含みます。巡回間の件数を加算すると重複計上します。
