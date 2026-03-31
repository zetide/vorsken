# AI CVE Report - Encoding Test
Date: 2026-03-31

## CVE-2024-9999
| Field | Value |
|-------|-------|
| AI Priority | CRITICAL |

**Risk Summary**
LangChainのPDFLoaderに存在するプロンプトインジェクション脆弱性です。悪意あるPDFを読み込ませることで埋め込まれた指示がLLMに実行されます。

**Attack Scenario**
攻撃者が細工したPDFをRAGシステムに投入し機密情報を窃取します。

**Mitigation**
- LangChain を最新バージョンにアップデート
- 外部入力ドキュメントのサニタイズ処理を追加