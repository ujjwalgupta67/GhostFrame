# Reproducing GhostFrame 2.2.0

Use Python 3.11 or newer on Windows 10/11, macOS or a common Linux distribution. Run commands from the extracted project directory.

## Base installation and website

```text
python -m venv .venv
```

Activate it with `.venv\Scripts\activate` on Windows or `source .venv/bin/activate` on macOS/Linux, then run:

```text
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
streamlit run app.py
```

Open `http://localhost:8501` if the browser does not open automatically. `start.bat` and `start.sh` perform dependency checks and start the same local website. ExifTool is optional.

## Tests

```text
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

## Optional local blockchain workflow

Install the optional Python dependencies:

```text
python -m pip install -r requirements-blockchain.txt
```

Install Foundry/Anvil separately for the development platform, then in terminal 1 run:

```text
anvil --host 127.0.0.1 --port 8545 --chain-id 31337
```

In terminal 2 run:

```text
python scripts/deploy_local_anchor.py --rpc http://127.0.0.1:8545
streamlit run app.py
```

Copy the printed chain ID, contract address, code hash and interface version into **Local Blockchain-Anchored Evidence Mode**. Use only loopback RPC endpoints and disposable unlocked development accounts.

The accepted contract artifact is already included. Development-only recompilation is:

```text
python scripts/compile_anchor_contract.py
```

Recompilation requires the pinned compiler configured by the script and must reproduce the documented contract identity before replacing any accepted artifact.

## Four-node Besu workflow

Install Docker Desktop/Engine with Compose, then install the optional Python dependencies. On macOS/Linux (or Windows through WSL/Git Bash with Docker Desktop integration):

```text
python -m pip install -r requirements-blockchain.txt
cd ghostframe-chain
./chain.sh start
export GF_BESU_DEV_KEY=0x8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63
./chain.sh deploy-app
cd ..
streamlit run app.py
```

The key is a public Besu tutorial key for isolated development only. Deployment creates `ghostframe-chain/build/ghostframe_deployment.json`; rerunning `deploy-app` validates and reuses the same contract. The command rejects a manifest whose genesis or deployed contract identity no longer matches.

Create evidence in the website using the four-node preset. To recheck a downloaded GFP package after restarting the website, use **Verify Evidence Package** or the terminal command:

```text
cd ghostframe-chain
./chain.sh verify-app /path/to/package.gfp
```

For a reversible availability demonstration, run `./chain.sh down 4`, check the website/status, then `./chain.sh up 4`. With one node offline, three validators can remain live but the default evidence policy does not claim four-of-four verification. With two validators offline, QBFT normally stops advancing until quorum is restored. Never use `reset` for an outage demonstration: reset deletes the chain identity and history.

## Deterministic release

```text
python scripts/build_release.py
python -c "import hashlib,pathlib; p=pathlib.Path('dist/GhostFrame-2.2.0-source.zip'); print(hashlib.sha256(p.read_bytes()).hexdigest())"
```

Build twice from unchanged source and compare SHA-256 values. Extract the archive into a new directory and repeat the base and optional-blockchain installation/test steps. Public-chain deployment is outside the 2.2.0 security model.
