# evm-state-proof-auditor

evm-state-proof-auditor verifies the account and storage proofs returned by `eth_getProof` against the `stateRoot` in an EVM block header. It is useful for checking account fields and contract storage without trusting an RPC response by itself.

## Example

This was run against Ethereum mainnet through `https://eth.drpc.org`.

    $ python evm_state_proof_auditor.py https://eth.drpc.org 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 latest 0x0 0x1 0x2
    address 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2
    account: PASS
    slot 0x0: PASS
    slot 0x1: PASS
    slot 0x2: PASS
    overall: PASS

A second live run used the Optimism mainnet RPC at block 2 for an on-chain system contract and slot 0.

    $ python evm_state_proof_auditor.py https://mainnet.optimism.io 0x8ce8c13d816fe6daf12d6fd9e4952e1fc88850af 2 0x0
    address 0x8ce8c13d816fe6daf12d6fd9e4952e1fc88850af
    account: PASS
    slot 0x0: PASS
    overall: PASS

## Usage

    python evm_state_proof_auditor.py RPC_URL ADDRESS BLOCK [SLOT ...]
    python evm_state_proof_auditor.py RPC_URL ADDRESS BLOCK [SLOT ...] --json

The address is an EVM address. Slots are optional hexadecimal storage slots. The RPC must support `eth_getBlockByNumber` and `eth_getProof`.

## How it works

The account key is Keccak-256 of the 20-byte address. Each storage key is Keccak-256 of its 32-byte slot word. The tool decodes RLP trie nodes and follows branch, extension, and leaf nodes. It handles hashed and embedded child nodes, odd and even compact paths, and valid absence proofs. Every hashed proof node is checked against the state root or account storage root before the returned account fields and values are compared.

## Tests

    python -m unittest -v

Tests do not access the network. The fixed WETH response fields and storage values come from a live Ethereum mainnet `eth_getProof` case. Parser tests cover compact paths, embedded nodes, and absence proofs.
