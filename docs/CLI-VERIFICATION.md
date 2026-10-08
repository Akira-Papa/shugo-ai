# 0.3.0 alpha 実装・3周レビューと検証

2026-10-08。前回0.2.1 hardeningの3周とは別に、今回の3OS/CLI追加を3周検討・修正した。外部監査や侵入防止の保証ではない。

## 完成した範囲

- Rust共通コアをGUIとheadless CLIから利用。no-default-featuresの依存ツリーにTauri/rfd/GTK/WebKitなし。
- CLI: scan/status/history、登録ファイル/観測識別付きbaseline、巡回/対策モデル設定、明示許可による一回のAI解析、watch、TCP接続、アクセスログ集計。
- watchはTCP/ログの追加取得、欠測coverage、SIGINT/SIGTERM終了、JSON/人向け表示に対応。daemon自動導入なし。AI自動送信なし。
- Mac/Windows/Linux別のパッケージ設定、native CI、秘密/runtimeを除いたsource archive。GitHub workflowは今回未実行、公開なし。

## 3回の修正

| 周 | レッド/グリーン/独立レビュー | 実装した改善 |
|---|---|---|
| 1 | headless境界、Windows空取得、TCP/log観測 | desktop feature分離、CLI、固定collector、3OS配布設定、Windows取得エラーの安全誤判定を修正 |
| 2 | status契約、読取失敗の成功終了、停止/機密/配布 | succeeded照合、exit/coverage整備、watch接続/log、人向け表示、SIGINT/SIGTERM、broken pipe処理、source allowlist |
| 3 | 非同期完了、取消境界、実通信観測、実bundle/初回起動 | 完了を確認後snapshot取得、settled成功条件、network128KiB/2048上限、検証用smoke同梱除外、Linux初回起動用private保存先 |

各担当所見は `docs/mtg/2026-10-08-cli-round{1,2,3}-{red,green,independent}.md`。最終起動検証で見つけた保存先修正も第3周で再査読した。

## 実行した検証

| 環境 | 証拠 |
|---|---|
| Mac arm64 | headless unit 83 pass・1 ignored、CLI integration 10 pass、desktop all-target clippy警告0、TS/Vite build、Playwright 21 pass |
| Mac live TCP | ignoredの人工loopback testを別途明示実行し1 pass。通常一覧取得も集約booleanで確認、生IPは証拠に保存せず |
| Linux arm64 / Debian 12 container | headless unit82 + CLI10 pass、clippy警告0、release build、実loopback/scan/watch/log/費用0 smoke |
| Linux x64 / Debian 12 container（DockerのCPUエミュレーション） | headless unit82 + CLI10 pass、clippy警告0、release build、実loopback/scan/watch/log/費用0 smoke |
| Windows x64 GNU | MinGWクロスbuildでGUI/CLI成功、CLI unit/integrationのtest実行ファイルもcompile成功。実Windowsでの実行は未確認 |
| Source package | allowlist/秘密/runtime除外/リンク拒否テスト2 pass、OS config smoke pass |

MacとLinuxのCLI runtime smokeは一時専用データと人工TCP/HTTPログのみを使った。Mac scan8項目、Linux6項目、watch2回、秘密query非出力、cloud=false、API0。Macの既存保護設定は読取のみ。実APIによるAI応答は未試験。

## GUIと配布の境界

Macはapp/dmgを生成。appをローカルad-hoc署名しstrict verify成功、専用一時データで6秒生存・schema2作成後に試験プロセスだけSIGTERMした。Developer ID署名/notarizationではない。PlaywrightはUIのブラウザー回帰試験で、各OS native WebViewの全操作ではない。

Linux arm64/x64ではdeb/rpmを生成し、Debian12 containerにdebをインストール。一般ユーザー・Xvfb/DBusでarm64は8秒、x64は10秒生存・private DB作成後、timeoutで終了した。portal警告あり。実Linuxデスクトップのダイアログ/トレイ/全操作やrpmインストールは未確認。

WindowsポータブルGUIはGNUビルドのexeと対応x64 WebView2Loader.dllを同梱するテスト版。OS標準DLLのほかWebView2 Runtimeが必要で、実起動・Defender/Firewall/PowerShell・NSIS・署名・SmartScreenは未確認。CIはMSVCの別経路であり、クロスビルドの成功と混同しない。

## 第3周で検出・修正した初回起動問題

LinuxのWebViewがsetup前にapp_local_data_dirを0755で作成し、旧コードは専用保存先の0700条件に反して起動に失敗した。新規時は所有者管理の親の下のprivateへ保存し、親の権限を勝手に変更しない。既存DB/WAL/SHM/journal/anchor/lockがあれば従来保存先を維持して通常の安全検査を通す。壊れたリンクや読取エラーを新規と誤判定しない。既存データの移動・初期化はしていない。明示SHUGO_DATA_DIRは従来通り。

## 未確認・制限

Windows実機、Intel Mac/WindowsARM64、全Linux distribution、署名済みinstallerの配布受入は未確認。AppImageは設定/CIのみ。OS全体の通信遮断/隔離/完全侵入防止は未実装。TCPはその時点の限定観測、ログは繰返し末尾集計で増分ではない。欠測を安全と扱わない。

raw実行ログはローカル `docs/evidence/cli-20261008/`。公開用source ZIPには含めない。配布物の種類とSHA-256は同梱artifacts.jsonを参照。
