# Shugo AI / 守護AI

無料・オープンソースの、PC / VPSのセキュリティ観測ツール。Tauri 2 + React + Rustのデスクトップアプリと、GUIを必要としないRust CLIです。

**v0.3.0-alpha / テスト配布版**。OSの保護設定・登録ファイルの変化を読取検査し、任意でAIによる整理・精査を利用できます。ウイルス対策の代替や、侵入の完全防止を提供するものではありません。

[ダウンロード](https://github.com/Akira-Papa/shugo-ai/releases/tag/v0.3.0-alpha) · [CLI操作](docs/CLI.md) · [検証状況](docs/CLI-VERIFICATION.md)

## 主な機能

- 手動・15分・1時間・登録ファイルのイベントによる巡回（デスクトップ）。
- 巡回AIと対策AIのモデルを別々に設定。OpenAI API / Anthropic APIに対応。
- AI未接続でもローカル検査が可能。外部AIの利用料は別途。
- CLIでscan / watch / connections / access-log。IP・生ログをAIへ送りません。
- クラウド送信は初期OFF。キーはメモリだけに保持し、任意のシェルコマンドをAIに実行させません。

## 配布と確認状況

| 対象 | 成果物 | 確認範囲 |
|---|---|---|
| Mac Apple Silicon | app / dmg / CLI | 実Macで起動・CLI試験。ad-hoc署名、公証なし |
| Windows x64 | portable GUI / CLI | GNUクロスビルド成功。実Windows起動未確認、署名なし |
| Linux x64 / arm64 | deb / rpm / CLI | Debian12 containerでdeb導入・GUI起動・CLI試験。rpm導入未確認 |

[OS別の詳細](docs/OS-MATRIX.md)。Windows GUIにはWebView2 Runtimeが必要です。Mac Intel、Windows ARM64、Linux muslは今回対象外です。

## CLI

```sh
shugo scan
shugo connections
shugo --json watch --interval 900 --connections
shugo access-log /absolute/path/access.log
```

watchはプロセスが生きている間の定期巡回。CtrlC/SIGTERMで停止。LinuxのTCP観測にはss/iproute2が必要です。アクセスログは繰り返し末尾を集計するため、巡回間の件数を加算しないでください。

## ソースから起動

デスクトップにはNode.js 22以上、Rust stableと各OSの[Tauri前提環境](https://v2.tauri.app/start/prerequisites/)が必要です。

```sh
npm ci
npm run tauri dev
```

ヘッドレスCLIはGUIライブラリ不要です。

```sh
cargo build --locked --release --manifest-path src-tauri/Cargo.toml --no-default-features --bin shugo
./src-tauri/target/release/shugo --help
```

## 検証

```sh
cargo test --locked --manifest-path src-tauri/Cargo.toml --no-default-features --lib --bin shugo --test cli
cargo clippy --locked --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
npm run build
npm test
```

3周の実装・レビューを反映しました。CI設定は3OSのnativeビルドを扱いますが、初回公開時のローカル確認は上表の範囲です。

## 制限

PC全体の通信遮断・ファイル隔離・侵入の完全防止は未実装。実行できる対策は守護AI自身の新規クラウド送信停止など限定範囲です。未取得や警告なしを「安全」と解釈しないでください。Codex / Claude Codeの直接呼び出しアダプターは準備中です。デスクトップはウィンドウを閉じると終了します。

## ライセンス

Apache-2.0。第三者依存は各コンポーネントのライセンスに従います。
