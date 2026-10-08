# 守護AI 0.3 — デスクトップ / サーバーCLI改善方針

決定日: 2026-10-08。既存0.2.1の改訂。配布成果物は既存保存先を維持し、CLIを新規追加する。機能要件（巡回/対策モデルの分離、手動/定期巡回、読取検査、分かりやすい結果）は維持する。

## 採用構成

Tauri 2 + React の画面と、Rustの共通コアを使う `shugo` CLI。Cargoのdesktop featureを外すとWebView・Tauri・ファイルダイアログ不要のバイナリを作る。VPSにはCLIだけを入れる。任意シェルや自律コード実行機能は持たせない。

GUIとCLIのデータディレクトリは既定で分離する。同一ディレクトリを明示するとinstance lockで排他する。個人用ディレクトリを0700、新規ファイルを0600として作り、広すぎる既存権限を勝手に変更しない。Windows ACLの保証はUnixと同一ではない。

## 機能と信頼境界

- `scan` / `status` / `history` / `watch`: 共通コアの読取検査。JSONと人向け表示。watchはプロセスが生きている間の定期実行。OSサービスの自動登録はしない。
- `files` / `baseline`: 利用者が指定したファイルを監視。比較基準は特定run/check/digest/観測時刻を照合して承認する。「変更なし」は安全の認定ではない。
- `connections`: その時点で権限の範囲で見えるTCPの相手IP/ポート/状態。受信方向・攻撃者・国・本人の特定はしない。短命接続や過去接続の網羅はできない。
- `access-log`: 利用者が指定したNginx/Apache形式ログを上限付きで読み、ログ記載IPの件数を集計する。URL・クエリ・User-Agent・本文・XFFを出力しない。プロキシやrealip設定、ログの真正性は別問題。
- `models` / `ai`: 巡回と対策の役割を分離。クラウドは明示許可時だけ。送信内容は固定の検査種別/状態/証拠ID。IPやログ本文をモデルへ送らない。キーは引数そのものでは渡さずキー用ファイルから読み、永続保存しない。
- AIの回答は未信頼データ。モデル名が強力でも権限は増やさない。OS通信遮断・ファイル隔離・完全防御は未実装。対策の現行実行範囲は守護AI自身のクラウド送信停止。

## 配布と検証

Mac arm64 app/dmg、Windows x64 NSIS、Linux x64 deb/rpm/AppImageをOS別設定・CIで生成する。CLIは同じ3OSとLinux arm64を検証可能な範囲で追加する。CI設定があることと実行成功は区別する。ローカルで実行できないOSを実機合格と書かない。署名・notarization・インストール実機受入は別の配布条件。

ソース配布は明示的なファイル範囲から作り、.local・データベース・キー・環境設定・個人用実行証拠を含めない。公開や外部Releaseは本作業では行わない。

## 3回の検証サイクル

1. 設計会議 → headless分離・CLI・接続観測・配布設定の実装 → unit/integration検証。
2. 攻撃/防御/運用の担当を横断して相互レビュー → 不正入力・未取得・秘密・排他・OS差分を改善。
3. 修正後の再レビュー → CLI実行/GUI回帰/配布物検証 → 残課題とOS別証拠を記録。

判断基準: **観測範囲・根拠・実行権限・復元可能性を説明できない動作は自動化しない。**

## 一次資料

- [Tauri配布](https://v2.tauri.app/distribute/)
- [Windows installer](https://v2.tauri.app/distribute/windows-installer/)
- [Linux AppImage](https://v2.tauri.app/distribute/appimage/)
- [Get-NetTCPConnection](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-nettcpconnection?view=windowsserver2025-ps)
- [ss manual](https://man7.org/linux/man-pages/man8/ss.8.html)
