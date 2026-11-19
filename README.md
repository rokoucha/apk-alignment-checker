# apk-alignment-checker

APKがGoogle Playの要求する16KBページサイズの要件を満たしているかチェックするツール

## インストール

[Releases](https://github.com/rokoucha/apk-alignment-checker/releases)からバイナリをダウンロードするか、`go install`してください。

```sh
go install github.com/rokoucha/apk-alignment-checker@latest
```

## 使い方

```sh
apk-alignment-checker app-release.apk
apk-alignment-checker -v libfoo.so        # プログラムヘッダも表示
apk-alignment-checker -json app.aab       # JSONで出力
apk-alignment-checker build/outputs/      # ディレクトリ配下を再帰的に検査
apk-alignment-checker -markdown report.md app.apk  # Markdownのレポートも書き出す
```

```
✘ FAIL  internal/checker/testdata/libdatastore_shared_counter.so
        ABI: arm64-v8a | LOAD align: 2**14 | GNU_RELRO: end 0xd000 (unaligned) | ZIP: n/a
        → GNU_RELRO: end 0xd000 is not 16KB aligned, mprotect(PROT_READ) extends to 0x10000
```

`.apk` `.aab` `.apks` `.so`と、それらを含むディレクトリを検査できます。
問題のあるライブラリが1つでもあれば終了コード`1`、ファイルが開けない・ZIPとして読めないなどの入力エラーは`2`を返します。

### GitHub Actions

Composite Actionとして呼び出すことで、GitHub Actionsでチェックできます。

```yaml
- id: check-16kb
  uses: rokoucha/apk-alignment-checker@<commit SHA> # vX.Y.Z
  with:
    working-directory: android
    paths: |
      app-*/build/outputs/apk/develop/debug/*.apk

- if: ${{ !cancelled() && steps.check-16kb.outcome == 'failure' }}
  uses: thollander/actions-comment-pull-request@24bffb9b452ba05a4f3f77933840a6a841d1b32b # v3.0.1
  with:
    comment-tag: 16kb-alignment
    message: |
      ## :warning: 16KB page size check failed

      ${{ steps.check-16kb.outputs.report }}
```

| input | 説明 |
| --- | --- |
| `paths` | 検査するファイル・ディレクトリ。空白か改行区切りで、glob (`**`を含む)を展開する。1つもマッチしなければエラー |
| `working-directory` | `paths`の基準ディレクトリ(デフォルト`.`) |

## 検査内容

64ビット(arm64-v8a, x86_64)のネイティブライブラリを対象に、以下のとおりチェックします。

| 検査 | 条件 | 理由 |
| --- | --- | --- |
| LOAD alignment | すべての`PT_LOAD`の`p_align`が16KB (2\*\*14)以上の2の冪である | 4KB境界のセグメントは16KBページではmmapできない |
| LOAD offset | `p_offset ≡ p_vaddr (mod 16KB)` | `p_align`だけ書き換えたライブラリはロードできない |
| GNU_RELRO | 終端(`p_vaddr + p_memsz`)が16KB境界、またはRELROが同じアドレスから始まる`PT_LOAD`全体を覆っている | bionic linkerはRELROを`page_end(終端)`までmprotectするため、終端がアラインされていないと後続のRWデータまで読み取り専用になりうる([linker_phdr.cpp](https://android.googlesource.com/platform/bionic/+/refs/heads/main/linker/linker_phdr.cpp)の`_extend_gnu_relro_prot_end`)。RWデータと重ならない場合も弾く |
| ZIP alignment | APKの`lib/`以下に非圧縮で格納された`.so`のデータオフセットが16KBにアラインされている(`zipalign -P 16`相当) | 非圧縮のライブラリはAPKから直接mmapされる。圧縮されている場合はインストール時に展開されるので対象外。AABはbundletoolがAPK生成時にアラインするので対象外 |

## 参考資料

- [16 KBのページサイズをサポートする | Android Developers](https://developer.android.com/guide/practices/page-sizes)

## ライセンス

Copyright (c) 2026 Rokoucha

Released under the MIT license, see LICENSE.
