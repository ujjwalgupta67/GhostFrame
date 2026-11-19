from __future__ import annotations

from pathlib import Path

import streamlit as st

from .besu import BesuDeploymentManifest
from .models import AnchorState
from .network import BESU_FOUR_NODE_ENDPOINTS, observe_network
from .network_models import MultiNodeAnchorVerification, NetworkAgreement


DEFAULT_MANIFEST = Path(__file__).resolve().parents[2] / "ghostframe-chain" / "build" / "ghostframe_deployment.json"


def load_default_besu_manifest() -> BesuDeploymentManifest:
    return BesuDeploymentManifest.load(DEFAULT_MANIFEST)


def render_network_dashboard(manifest: BesuDeploymentManifest, *, key: str) -> None:
    st.markdown("**Four-node Besu network**")
    st.caption(f"Chain 4242 · QBFT · profile `{manifest.network_profile}`")
    if st.button("Check four-node network", key=key, width="stretch"):
        st.session_state[f"{key}_observation"] = observe_network(
            expected_chain_id=manifest.chain_id,
            expected_genesis_hash=manifest.genesis_hash,
        )
    observation = st.session_state.get(f"{key}_observation")
    if observation is None:
        st.info("Network status has not been checked in this session.")
        return
    columns = st.columns(4)
    for column, node in zip(columns, observation.nodes):
        with column:
            st.markdown(f"**{node.label}**")
            if node.available:
                st.success("UP")
                st.caption(f"Block {node.block_height} · Peers {node.peer_count}")
                st.caption("Synchronizing" if node.syncing else "Synchronized")
                identity_ok = (
                    node.chain_id == manifest.chain_id
                    and node.genesis_hash == manifest.genesis_hash.lower()
                )
                st.caption("Chain identity: OK" if identity_ok else "Chain identity: MISMATCH")
                if node.current_block_hash:
                    st.caption(f"Head: `{node.current_block_hash[:14]}…`")
                if node.latency_ms is not None:
                    st.caption(f"RPC latency: {node.latency_ms:.0f} ms")
            else:
                st.error("UNAVAILABLE")
                st.caption(node.error or "No validated response")
    if observation.agreement == NetworkAgreement.ALL_AGREE:
        st.success(observation.detail)
    elif observation.agreement in {NetworkAgreement.PARTIAL_AGREEMENT, NetworkAgreement.CATCHING_UP}:
        st.warning(observation.detail)
    else:
        st.error(observation.detail)
    if observation.common_height is not None:
        st.caption(f"Ledger comparison used common block height {observation.common_height}.")
    observed = next((node.observed_at for node in observation.nodes if node.observed_at), None)
    if observed:
        st.caption(f"Last checked: {observed}")


def render_multinode_result(title: str, result: MultiNodeAnchorVerification) -> None:
    st.markdown(f"**{title}: {result.state.value}**")
    if result.state == AnchorState.CONFIRMED:
        st.success(result.detail)
    elif result.state == AnchorState.PENDING:
        st.warning(result.detail)
    else:
        st.error(result.detail)
    columns = st.columns(4)
    for column, item in zip(columns, result.results):
        with column:
            st.caption(item.label)
            if item.state == AnchorState.CONFIRMED:
                st.success("VERIFIED")
            elif item.state == AnchorState.PENDING:
                st.warning("PENDING")
            else:
                st.error("NOT VERIFIED")
            st.caption(item.detail)
