# sing-box local build helpers

name := "sing-box"
tags := "with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_tailscale,with_ccm,with_ocm,badlinkname,tfogo_checklinkname0"
main := "./cmd/sing-box"
deploy_target := "homelab/file/singbox/"

# 显式声明默认入口, 避免 recipe 顺序变化后默认行为漂移
[private]
default: help

# 列出可用 recipe (默认入口)
help:
    @just --list

# 清理本地构建产物
clean:
    rm -f {{name}}
    rm -rf dist/

# 按 Makefile 同款 tags/ldflags 构建当前平台二进制
build:
    #!/usr/bin/env bash
    set -euo pipefail
    version="$(CGO_ENABLED=0 go run ./cmd/internal/read_tag)"
    go build -v -trimpath \
      -ldflags "-X 'github.com/sagernet/sing-box/constant.Version=${version}' -X 'internal/godebug.defaultGODEBUG=multipathtcp=0' -s -w -buildid= -checklinkname=0" \
      -tags "{{tags}}" \
      -o "{{name}}" \
      "{{main}}"

# 一次性构建部署所需的两个平台, 避免上传不同提交生成的产物
build-release:
    #!/usr/bin/env bash
    set -euo pipefail
    version="$(CGO_ENABLED=0 go run ./cmd/internal/read_tag)"
    ldflags="-X 'github.com/sagernet/sing-box/constant.Version=${version}' -X 'internal/godebug.defaultGODEBUG=multipathtcp=0' -s -w -buildid= -checklinkname=0"
    mkdir -p dist

    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -v -trimpath \
      -ldflags "$ldflags" \
      -tags "{{tags}}" \
      -o "dist/{{name}}-linux-amd64" \
      "{{main}}"

    CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -v -trimpath \
      -ldflags "$ldflags" \
      -tags "{{tags}}" \
      -o "dist/{{name}}-macos-arm64" \
      "{{main}}"

# 按版本目录上传, 避免新产物覆盖旧版本导致无法回滚
deploy: build-release
    #!/usr/bin/env bash
    set -euo pipefail
    version="$(CGO_ENABLED=0 go run ./cmd/internal/read_tag | sed -E 's/-[0-9a-f]{8}$//')"
    target="{{deploy_target}}binary/${version}/"
    mc cp \
      "dist/{{name}}-linux-amd64" \
      "dist/{{name}}-macos-arm64" \
      "$target"

# 构建后 mv 到 GOPATH/bin (实体文件, 非 symlink; develop 再链到 gobin)
install: build
    #!/usr/bin/env bash
    set -euo pipefail
    gobin="$(go env GOPATH)/bin"
    mkdir -p "$gobin" "$HOME/develop/sing-box"
    rm -f "$gobin/sing-box"
    mv -f "$PWD/sing-box" "$gobin/sing-box"
    ln -sfn "$gobin/sing-box" "$HOME/develop/sing-box/sing-box"
    "$gobin/sing-box" version
