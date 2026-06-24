# VeriNode--Core

Core smart contracts for the VeriNode Decentralized Savings Circle protocol, providing a trustless Rotating Savings and Credit Association (ROSCA) infrastructure on Stellar Soroban.

## 🚀 Key Features
* **Decentralized ROSCA Protocol:** Create and join savings circles with custom contribution rules, cycle rollovers, and automated payouts.
* **Collateralized Entry & Slashing:** Built-in collateral requirements for high-value groups with slashing mechanisms for defaulting members.
* **Leniency Voting & Buddy System:** Governance extensions for grace periods via democratic voting and buddy pairing safety fallback payments.

## 🛠️ Tech Stack
* **Language/Framework:** Rust / Soroban WASM
* **Key Dependencies:** `soroban-sdk`

## 📦 Getting Started

### Prerequisites
Ensure you have the required toolchains installed:
* Rust toolchain (cargo, rustc)
* Stellar CLI / Soroban CLI

### Installation & Local Setup
```bash
# Clone the repository (if running manually)
git clone https://github.com/VeriNode-Labs/VeriNode--Core

# Build the smart contracts
cargo build --target wasm32-unknown-unknown --release

# Run the test suite
cargo test
```

## 🤝 Contributing
Contributions are highly welcome. Please ensure your commits are cryptographically signed using GPG or SSH keys. For major structural changes, please open an issue first to discuss your proposal.
