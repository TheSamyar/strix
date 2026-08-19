---
name: web3_smart_contracts
description: "Web3/dApp security: Solidity contract flaws (reentrancy, access control, oracle/price manipulation, precision), signature replay, and the front-end-to-contract trust boundary"
---

# Web3 / Smart Contracts

dApps have two attack surfaces: the on-chain contracts (immutable, hold value) and the off-chain front-end/backend that talks to them. Contract bugs are usually the high-severity ones because state and funds are public and permanent. This skill assumes a testnet/fork or explicitly authorized target — never test live mainnet contracts with real value.

## What To Map First

- **Contracts:** addresses, verified source (Etherscan/Sourcify), compiler version, proxy pattern (Transparent/UUPS/Diamond) and the implementation behind it.
- **Roles & ownership:** `owner`, `admin`, `DEFAULT_ADMIN_ROLE`, multisig vs EOA, timelocks, upgradeability.
- **Value flows:** deposit/withdraw, mint/burn, swap, stake, reward, bridge, fee paths.
- **External dependencies:** price oracles (Chainlink vs on-chain AMM spot), other protocols called, tokens accepted (incl. fee-on-transfer / rebasing / ERC-777 hooks).
- **Off-chain:** how the front-end constructs transactions, what it signs, backend endpoints that trust chain data or user-supplied addresses.

Tools: Foundry (`forge`, `cast`), Slither/Mythril for static analysis, a mainnet fork for realistic exploit PoCs.

## Key Vulnerabilities

### Reentrancy

External call before state update lets the callee re-enter and drain.

- Classic: `call{value:}` / token transfer to attacker before balance is decremented — recursive withdraw.
- Cross-function & read-only reentrancy: state is mid-update when a *different* function (or a view used by another protocol) reads it.
- ERC-777 `tokensReceived` / ERC-721 `onERCReceived` hooks give attackers a callback even on "plain" transfers.
- Check for the checks-effects-interactions pattern and `nonReentrant` guards on every value-moving path.

### Access Control Gaps

- Missing/incorrect modifier on sensitive functions (`initialize`, `mint`, `setOwner`, `upgradeTo`, `withdraw`).
- **Uninitialized proxy:** an unprotected `initialize()` an attacker can call to seize ownership.
- `tx.origin` used for auth (phishable) instead of `msg.sender`.
- Role-check present but on the wrong role, or `onlyOwner` where owner is an EOA that can be compromised.

### Oracle / Price Manipulation

- Spot price read from an AMM pool (`getReserves`, `balanceOf`) manipulable within a single **flash-loan** transaction → mispriced mint/borrow/liquidation.
- Stale/unchecked oracle data (no `updatedAt`/`answeredInRound` validation, no min/max bounds).
- Single-source oracle with no TWAP or deviation check.

### Arithmetic & Precision

- Rounding/precision loss in share/asset math (first-depositor inflation attack on vaults).
- Division-before-multiplication truncation, unchecked `unchecked{}` blocks, unsafe casts.
- (Pre-0.8) integer over/underflow; post-0.8 look at explicit `unchecked`.

### Signature & Replay

- Missing nonce or chainId in signed messages → replay across txs or chains.
- EIP-712 domain separator not binding contract/chain → cross-contract signature reuse.
- `ecrecover` malleability (s-value) and unchecked `address(0)` return.
- Permit/meta-tx flows where the relayer or a third party can front-run or replay.

### Front-Running / MEV

- Predictable pending txs (approve/swap) sandwiched; missing slippage/deadline params.
- Commit-reveal absent where ordering matters (auctions, claims).

### Denial of Service

- Unbounded loops over user-controlled arrays (gas-out).
- Push-payment to an address that reverts, blocking a queue (use pull-payment).
- Griefing via forced failure of an external call.

### Front-End → Contract Trust Boundary

- Backend/front-end trusting `from`/amount decoded from an unverified tx or an event without confirming on-chain finality.
- Signature verification done client-side only.
- Contract address or ABI taken from user input / a mutable config an attacker can swap (phishing a malicious contract).
- Chain data (balances, ownership) trusted without re-reading from a node the app controls.

## Testing Methodology

1. **Recon** — pull verified source, identify proxy/impl, roles, value flows, oracles, token quirks.
2. **Static** — Slither/Mythril for reentrancy, access-control, arithmetic flags; triage findings (many are noise).
3. **Fork & PoC** — on a mainnet fork or testnet, write Foundry tests that actually execute the exploit (drain, mint, seize ownership, manipulate price via flash loan).
4. **Signature/replay** — replay signed messages across nonce/chain/contract.
5. **Off-chain** — test the front-end/backend trust of chain data and user-supplied addresses.

## Validation Requirements

- A runnable Foundry/Hardhat PoC on a fork/testnet showing the concrete impact (funds moved, ownership taken, price manipulated) — not just a static-analyzer flag.
- Exact function, call sequence, and starting/ending state (balances, owner).
- For off-chain issues, the request/response proving the app trusted unverified chain data.
- Never execute value-moving exploits against live mainnet contracts holding real funds.
