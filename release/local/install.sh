#!/usr/bin/env bash

set -e -o pipefail

if [ -d /usr/local/go ]; then
  export PATH="$PATH:/usr/local/go/bin"
fi

DIR=$(dirname "$0")
PROJECT=$DIR/../..

pushd $PROJECT
TAGS="with_quic,with_wireguard,with_utls,with_clash_api,with_gvisor" make build
popd

sudo cp $(go env GOPATH)/bin/sing-box /usr/local/bin/
sudo mkdir -p /usr/local/etc/sing-box
sudo cp $PROJECT/release/config/config.json /usr/local/etc/sing-box/config.json
sudo cp $DIR/sing-box.service /etc/systemd/system
sudo systemctl daemon-reload
