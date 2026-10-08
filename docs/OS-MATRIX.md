# 3OS 配布・検証状況

2026-10-08 / v0.3.0 alpha。実行証拠は [CLI-VERIFICATION.md](CLI-VERIFICATION.md)。CI定義と実機確認を分ける。

| 対象 | 用意した形式 | 確認範囲 |
|---|---|---|
| macOS Apple Silicon | app・dmg・CLI | Macでビルド、app起動、CLI scan/watch/TCP/log、回帰テスト。ad-hoc署名、notarizationなし |
| Windows x64 | portable GUI exe + WebView2Loader.dll・CLI exe | Linux上MinGW GNUクロスbuild。CLI test実行ファイルのcompile。実Windows起動/インストールは未確認 |
| Linux arm64 | deb・rpm・CLI | Debian12 containerでビルド、deb install・GUI初回起動、CLI実行テスト。rpm installは未確認 |
| Linux x64 | CLI、GUI deb/rpm | Debian12 containerでCLI実行、deb/rpm生成、deb install・一般ユーザーGUI初回起動を確認 |

Linux containerのkernel/CPU/ファイル/ネットワーク観測はcontainerが見える範囲であり、ホストPC全体の検査ではない。x64 containerはApple Silicon上のCPUエミュレーション。物理VPSや全distributionでの受入とは異なる。

CIはMacarm64（macos-14）/Windowsx64 MSVC（windows-2022）/Linuxx64（ubuntu-24.04）で、CLIを独立test/build、GUIをnative bundleし、artifactを保存する定義。実際のGitHub workflowは今回未実行。contents read、credentials保存なし、自動Release/tag/publishなし。MSVCとGNUは別の検証経路。

GUI設定はMac app/dmg、Windows NSIS currentUser、Linux deb/rpm/AppImage。AppImage/WindowsNSISは今回のローカル配布物として未生成。署名済み配布/SmartScreen/Gatekeeper受入/全操作は未確認。Mac Intel/universal、WindowsARM64、muslは今回対象外。

Windows portable GUIではexeの隣にx64 WebView2Loader.dllを置く。WebView2 Runtimeは別途必要。LoaderはRuntimeそのものではない。[Microsoft公式配布説明](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/distribution)。利用者PCへのRuntimeインストールや保護設定変更はこの作業ではしていない。

LinuxはGTK/WebKitGTK 4.1等のGUI依存が必要だが、no-default-features CLIには不要。CLIのTCP観測はss/iproute2が必要。CLI watchはforegroundでありサービス登録は自動化しない。

配布ソースはscripts/source-archive.pyのallowlistで作り、.local・DB・keys・.env・raw evidenceを除外する。tests/fixture用smokeはexamplesへ移し、アプリには同梱しない。

## 一次資料

- [Tauri配布](https://v2.tauri.app/distribute/)
- [Tauri OS別設定](https://v2.tauri.app/reference/config/#platform-specific-configuration)
- [Windows installer](https://v2.tauri.app/distribute/windows-installer/)
- [Linux AppImage](https://v2.tauri.app/distribute/appimage/)
- [GitHub runner仕様](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
