#!/usr/bin/env bash
# GhostFrame 4-node blockchain: one script for everything.
# Run ./chain.sh with no arguments to see the commands.
set -euo pipefail
cd "$(dirname "$0")"

IMAGE="${BESU_IMAGE:-hyperledger/besu:25.12.0}"
PY=".venv/bin/python"
APP_PY="../.venv/bin/python"

say()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
fail() { printf '\n\033[1;31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

need_docker() {
  command -v docker >/dev/null 2>&1 || fail "Docker not found. Install Docker Desktop: https://www.docker.com/products/docker-desktop/"
  docker info >/dev/null 2>&1 || fail "Docker Desktop is not running. Open the Docker app from Applications, wait until the whale icon in the menu bar stops animating, then run this again."
}

rpc_up() { # $1 = port
  curl -s -m 2 -X POST -H 'Content-Type: application/json' \
    --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
    "http://127.0.0.1:$1" 2>/dev/null | grep -q '"result"'
}

cmd_setup() {
  if [ -f build/genesis.json ] && [ -f .env ]; then
    echo "The network is already set up (keys + genesis ready). To start over with a new one: ./chain.sh reset"
    return 0
  fi
  need_docker
  say "Downloading the Besu image (~300 MB the first time, this can take a few minutes)"
  docker pull "$IMAGE"

  say "Creating 4 validator keys and the genesis file"
  rm -rf build nodes .env
  mkdir -p build
  cp config/qbftConfigFile.json build/qbftConfigFile.json
  # Call besu directly: the image's default entrypoint (as root) runs the command
  # twice, and the second run fails with "Output directory already exists".
  docker run --rm --entrypoint /opt/besu/bin/besu -v "$PWD/build:/build" "$IMAGE" \
    operator generate-blockchain-config \
    --config-file=/build/qbftConfigFile.json \
    --to=/build/networkFiles \
    --private-key-file-name=key >/dev/null
  cp build/networkFiles/genesis.json build/genesis.json

  i=1
  for d in build/networkFiles/keys/*/; do
    mkdir -p "nodes/node$i/data"
    cp "$d/key" "$d/key.pub" "nodes/node$i/"
    basename "$d" > "nodes/node$i/validator_address"
    i=$((i + 1))
  done
  [ "$i" -eq 5 ] || fail "Expected 4 keys, found $((i - 1))."

  # Every node knows all four enodes, so the network survives any single node going down.
  boot=""
  for n in 1 2 3 4; do
    pub="$(sed 's/^0x//' "nodes/node$n/key.pub" | tr -d '[:space:]')"
    boot="${boot},enode://${pub}@172.16.239.1${n}:30303"
  done
  echo "BOOTNODES=${boot#,}" > .env
  say "Setup done. Validators:"
  for n in 1 2 3 4; do echo "  node$n  $(cat nodes/node$n/validator_address)"; done
}

cmd_tools() {
  command -v python3 >/dev/null 2>&1 || fail "python3 not found. Install Python 3.10 or newer, then try again."
  say "Installing Python tools (into the .venv folder; nothing on your system changes)"
  [ -d .venv ] || python3 -m venv .venv
  .venv/bin/pip install --quiet --upgrade pip
  .venv/bin/pip install --quiet -r tools/requirements.txt
  say "Tools ready."
}

cmd_start() {
  need_docker
  [ -f .env ] || cmd_setup
  say "Starting 4 nodes"
  docker compose up -d
  printf 'Waiting for Node 1'
  for _ in $(seq 1 60); do
    if rpc_up 8545; then echo " ready."; break; fi
    printf '.'; sleep 2
  done
  rpc_up 8545 || fail "Node 1 did not start within 2 minutes. Check its logs: ./chain.sh logs 1"
  sleep 6   # give peers a moment to connect and produce blocks
  cmd_status || true
}

cmd_stop() {
  need_docker
  say "Stopping all nodes (data is kept)"
  docker compose stop
}

cmd_status() {
  python3 tools/check_nodes.py "$@"
}

cmd_node() { # down|up N
  local action="$1" n="${2:-}"
  case "$n" in 1|2|3|4) ;; *) fail "Give a node number from 1 to 4, for example: ./chain.sh $action 3";; esac
  need_docker
  if [ "$action" = down ]; then
    say "Stopping node $n (simulating a failure)"
    docker compose stop "node$n"
  else
    say "Starting node $n again"
    docker compose start "node$n"
    echo "The node needs ~10-30 seconds to reconnect and sync. Then run: ./chain.sh status"
  fi
}

cmd_logs() {
  local n="${1:-1}"
  need_docker
  docker logs -f --tail 40 "gf-node$n"
}

cmd_demo() {
  [ -x "$PY" ] || cmd_tools
  local f="${1:-}"
  if [ -z "$f" ]; then
    mkdir -p build
    f="build/sample_document.txt"
    # A fresh timestamp each run gives a new hash, so every demo makes a new record.
    printf 'GhostFrame demo document\nProposal amount: Rs 5,00,000\nCreated: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" > "$f"
  fi
  "$PY" tools/demo_anchor.py deploy --if-missing
  "$PY" tools/demo_anchor.py anchor "$f" || true
  "$PY" tools/demo_anchor.py verify "$f"
}

cmd_deploy_ghostframe() {
  [ -x "$APP_PY" ] || fail "GhostFrame's main .venv is missing. Install the project requirements first."
  "$APP_PY" tools/deploy_ghostframe.py
}

cmd_verify_ghostframe() {
  [ -x "$APP_PY" ] || fail "GhostFrame's main .venv is missing. Install the project requirements first."
  local package="${1:-}"
  [ -n "$package" ] || fail "Give a GFP package path, for example: ./chain.sh verify-app evidence.gfp"
  "$APP_PY" tools/verify_ghostframe.py "$package"
}

cmd_reset() {
  printf 'This will DELETE the whole blockchain and all keys. Are you sure? (type yes): '
  read -r ans
  [ "$ans" = yes ] || { echo "Cancelled."; return 0; }
  need_docker
  docker compose down --remove-orphans 2>/dev/null || true
  rm -rf build nodes .env
  say "Reset done. Start a fresh network with: ./chain.sh start"
}

usage() {
  cat <<'EOF'
GhostFrame blockchain (4 Besu nodes, QBFT)

  ./chain.sh start        start the network (sets everything up the first time)
  ./chain.sh status       health of all 4 nodes + shared ledger check
  ./chain.sh stop         stop everything (data is kept)

  ./chain.sh tools        install the Python tools (once)
  ./chain.sh demo [FILE]  record a file's hash on chain and verify it on every node
  ./chain.sh deploy-app   deploy or validate the real GhostFrameAnchor contract
  ./chain.sh verify-app FILE  verify a GFP 2.0 package through all four nodes

  ./chain.sh down N       stop node N  (failure demo, N = 1..4)
  ./chain.sh up N         start node N again
  ./chain.sh logs N       live logs of node N (Ctrl+C to exit)

  ./chain.sh reset        delete everything and start over (new keys)
EOF
}

case "${1:-}" in
  setup)  cmd_setup ;;
  start)  cmd_start ;;
  stop)   cmd_stop ;;
  status) shift; cmd_status "$@" ;;
  tools)  cmd_tools ;;
  demo)   shift; cmd_demo "${1:-}" ;;
  deploy-app) cmd_deploy_ghostframe ;;
  verify-app) shift; cmd_verify_ghostframe "${1:-}" ;;
  down|up) cmd_node "$1" "${2:-}" ;;
  logs)   cmd_logs "${2:-1}" ;;
  reset)  cmd_reset ;;
  *)      usage ;;
esac
