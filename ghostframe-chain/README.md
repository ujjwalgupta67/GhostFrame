# GhostFrame Blockchain: 4-Node Local Network

This folder runs a **real multi-node blockchain** for GhostFrame: 4 Hyperledger Besu nodes that keep one shared ledger using QBFT consensus. Everything runs inside Docker, and every task is a single command: `./chain.sh`.

```
 Your Mac
 ┌──────────────────────────────────────────────────────────┐
 │  chain.sh / Python tools / (later) GhostFrame app        │
 │        │  http://127.0.0.1:8545                          │
 │        ▼                                                 │
 │  ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐  │
 │  │ Node 1  │◄─►│ Node 2  │◄─►│ Node 3  │◄─►│ Node 4  │  │
 │  │processing│  │ client  │   │ auditor │   │validator│  │
 │  │  :8545  │   │  :8546  │   │  :8547  │   │  :8548  │  │
 │  └─────────┘   └─────────┘   └─────────┘   └─────────┘  │
 │   Docker containers · every block needs 3 of 4 to sign   │
 └──────────────────────────────────────────────────────────┘
```

---

## Step 0: Before you start (one time only)

1. **Open Docker Desktop or start Docker Engine.** Wait until `docker info` works. Windows users should run this folder in WSL or Git Bash with Docker Desktop integration.
2. **Give Docker enough memory.** Docker Desktop → Settings (⚙️) → Resources → set Memory to at least **4 GB** → "Apply & restart".
3. **Open Terminal.** Press `Cmd + Space`, type `Terminal`, press Enter.

## Step 1: Open the project folder

Open a terminal in the main GhostFrame project, then enter this folder:

```bash
cd ghostframe-chain
chmod +x chain.sh
```

> Every command after this must run inside this folder. If you close Terminal and open it again, run `cd ~/Desktop/ghostframe-chain` first.

## Step 2: Start the blockchain

```bash
./chain.sh start
```

**The first time**, this can take 3–5 minutes: it downloads Besu (~300 MB), creates keys for the 4 nodes and starts the network. At the end you should see something like this:

```
Node                  Status       Block  Peers
-----------------------------------------------
Node 1 (processing)   UP               6      3
Node 2 (client)       UP               6      3
Node 3 (auditor)      UP               6      3
Node 4 (validator)    UP               6      3
...
  => SHARED LEDGER OK: all live nodes hold the same chain
```

This means: all 4 nodes are running, each node is connected to the other 3 (Peers = 3), and all four hold the same blocks. 🎉

## Step 3: Install the Python tools (one time only)

```bash
./chain.sh tools
```

> If your Mac shows a popup asking to install "command line developer tools", click **Install**. When that finishes, run this command again.

## Step 4: First demo: record a file on the blockchain

```bash
./chain.sh demo
```

This creates a sample document, puts its SHA-256 hash on the chain, and then checks it **on each of the four nodes separately**:

```
  Node 1 (processing)   FOUND, anchored in block #28
  Node 2 (client)       FOUND, anchored in block #28
  Node 3 (auditor)      FOUND, anchored in block #28
  Node 4 (validator)    FOUND, anchored in block #28

VERIFIED: 4 independent node(s) hold this exact file's hash.
```

You can also use any file of your own (a photo, a PDF, anything). Type `./chain.sh demo ` and then drag the file into the Terminal window; its path is filled in for you:

```bash
./chain.sh demo ~/Desktop/my_file.pdf
```

> Only the file's **hash** goes on the chain. The file itself, its name and its contents never go on the blockchain.

## Step 5: Tamper demo (change a file, it gets caught)

```bash
cp build/sample_document.txt build/tampered.txt
echo "one line secretly changed" >> build/tampered.txt
.venv/bin/python tools/demo_anchor.py verify build/tampered.txt
```

The result is `NOT FOUND` and `FAILED`. Changing even one byte changes the hash completely, so a modified file no longer matches the chain.

## Step 6: Node failure demo (shows consensus at work)

```bash
./chain.sh down 3                # stop Node 3 (one organisation goes offline)
./chain.sh status                # 3 of 4 UP: blocks are still being made
./chain.sh demo                  # a new record still goes through

./chain.sh down 2                # now stop Node 2 as well
./chain.sh status                # only 2 UP: chain is PAUSED (it needs 3)

./chain.sh up 2                  # bring them back
./chain.sh up 3
```

After the nodes come back, **wait 1–2 minutes**, then run `./chain.sh status`. The block number starts rising again, and Node 3 catches up on the records it missed (sync).

> This 1–2 minute wait is normal: QBFT only starts a new round after a safety timer runs out.

## Step 7: Done? Stop it

```bash
./chain.sh stop
```

Your data is kept. Next time, `./chain.sh start` picks up where you left off.

---

## All commands in one place

| Command | What it does |
|---|---|
| `./chain.sh start` | Start the network (sets everything up the first time) |
| `./chain.sh status` | Health of all 4 nodes + shared ledger check |
| `./chain.sh stop` | Stop everything, data is kept |
| `./chain.sh tools` | Install the Python tools (once) |
| `./chain.sh demo [FILE]` | Record a demonstration file hash on `DemoAnchor` + verify it |
| `./chain.sh deploy-app` | Deploy or validate the real `GhostFrameAnchor` and manifest |
| `./chain.sh verify-app FILE` | Verify a GFP 2.0 package through all four nodes |
| `./chain.sh down N` / `up N` | Stop / start node N (N = 1 to 4) |
| `./chain.sh logs N` | Live logs of node N (press `Ctrl + C` to exit) |
| `./chain.sh reset` | Delete everything and create a brand-new network |
| `./chain.sh status --tx 0x…` | Check whether one transaction is on all 4 nodes |

## If something goes wrong

| Problem | Solution |
|---|---|
| `Docker Desktop is not running` | Open the Docker app, wait for the whale icon to stop animating, then try again |
| `permission denied: ./chain.sh` | Run `chmod +x chain.sh` |
| `port is already allocated` / 8545 busy | Another local service (such as Anvil) is using the port. Stop that service, then retry. |
| Logs show `ERROR ... Invalid system call address ... beac02` | **Ignore it.** It is a harmless message; blocks keep being made normally |
| Block number not rising after restarting nodes | Wait 1–2 minutes (see Step 6 above) |
| Temporary outage or a stopped node | Run `./chain.sh up N`, wait for synchronization, then check `./chain.sh status`. Do not reset unless you intentionally want a new chain. |

## What's inside (if you're curious)

```
ghostframe-chain/
├── chain.sh                  ← every command
├── docker-compose.yml        ← definition of the 4 Besu nodes
├── config/
│   ├── qbftConfigFile.json   ← genesis: chain ID 4242, QBFT, free gas
│   └── node-config.toml      ← settings shared by every node
├── contracts/DemoAnchor.sol  ← small demo contract (stores a file hash once)
├── tools/
│   ├── check_nodes.py        ← compares the nodes
│   └── demo_anchor.py        ← deploy / anchor / verify
├── build/   (auto)           ← genesis + generated files
└── nodes/   (auto)           ← each node's key and blockchain data
```

**Network details:** chain ID `4242` · Besu `25.12.0` · QBFT, one block every ~2 seconds · gas price 0 · RPC only on `127.0.0.1` (nothing outside your Mac can connect).

⚠️ **Demo only:** the dev account's private key is a publicly known key from the Besu documentation. Never use this setup on a real or public network.

## Connect the GhostFrame website

Install the main project's optional dependencies first. Then configure the public Besu tutorial account only in the current terminal and deploy the real contract:

```bash
cd ghostframe-chain
export GF_BESU_DEV_KEY='0x8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63'
./chain.sh deploy-app
cd ..
streamlit run app.py
```

Choose **Local Blockchain-Anchored Evidence Mode** and **Four-node Hyperledger Besu**. GhostFrame reads the generated deployment manifest automatically. `DemoAnchor` remains a separate terminal demonstration and is never used for GFP evidence.

The displayed development key is public and unsafe for real value. It stays in the server process environment; the website never asks for it. All four validators are controlled by this one local operator, so this setup demonstrates replicated ledger state and QBFT outage behavior—not four independent organisations.

## Recovery and reset warning

Use `down N` and `up N` for reversible outage demonstrations. One unavailable validator normally leaves three-node liveness, but GhostFrame will not call that four-of-four verification. Two unavailable validators normally pause new blocks until quorum returns.

`./chain.sh reset` is destructive: it deletes validator identities, ledger history and the generated GhostFrame deployment manifest. Existing GFP packages remain locally verifiable, but their old transactions cannot be checked on the replacement chain. Never use reset merely to fix a temporary node outage.
