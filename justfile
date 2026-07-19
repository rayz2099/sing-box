# sing-box local build helpers

name := "sing-box"
tags := "with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_tailscale,with_ccm,with_ocm,badlinkname,tfogo_checklinkname0"
main := "./cmd/sing-box"

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
