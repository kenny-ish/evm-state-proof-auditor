#!/usr/bin/env python3
"""Verify eth_getProof account and storage proofs against an EVM state root."""
import argparse
import json
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

_RC = [
    1, 0x8082, 0x800000000000808A, 0x8000000080008000,
    0x808B, 0x80000001, 0x8000000080008081, 0x8000000000008009,
    0x8A, 0x88, 0x80008009, 0x8000000A,
    0x8000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x80000001, 0x8000000080008008,
]
_ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]
_MASK = (1 << 64) - 1


def _rol(value, shift):
    shift %= 64
    return ((value << shift) | (value >> (64 - shift))) & _MASK if shift else value


def _keccak_f(state):
    for rc in _RC:
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= d[x]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol(state[x + 5 * y], _ROT[x][y])
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])
        state[0] ^= rc


def keccak256(data):
    rate = 136
    padded = bytearray(data)
    padded.append(1)
    padded.extend(b"\x00" * ((rate - len(padded) % rate - 1) % rate))
    padded.append(0x80)
    state = [0] * 25
    for start in range(0, len(padded), rate):
        block = padded[start:start + rate]
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(block[i * 8:(i + 1) * 8], "little")
        _keccak_f(state)
    out = bytearray()
    while len(out) < 32:
        for i in range(rate // 8):
            out.extend(state[i].to_bytes(8, "little"))
        if len(out) < 32:
            _keccak_f(state)
    return bytes(out[:32])


def rlp_decode(data):
    """Decode one complete RLP item and reject trailing bytes."""
    def read(pos):
        if pos >= len(data):
            raise ValueError("truncated RLP")
        prefix = data[pos]
        if prefix <= 0x7f:
            return data[pos:pos + 1], pos + 1
        if prefix <= 0xb7:
            length = prefix - 0x80
            end = pos + 1 + length
            if end > len(data):
                raise ValueError("truncated string")
            if length == 1 and data[pos + 1] < 0x80:
                raise ValueError("non-canonical string")
            return data[pos + 1:end], end
        if prefix <= 0xbf:
            length_size = prefix - 0xb7
            end_len = pos + 1 + length_size
            if end_len > len(data):
                raise ValueError("truncated long string length")
            length = int.from_bytes(data[pos + 1:end_len], "big")
            if length < 56 or (length_size > 1 and data[pos + 1] == 0):
                raise ValueError("non-canonical long string")
            end = end_len + length
            if end > len(data):
                raise ValueError("truncated long string")
            return data[end_len:end], end
        if prefix <= 0xf7:
            length = prefix - 0xc0
            end = pos + 1 + length
            if end > len(data):
                raise ValueError("truncated list")
            values, cursor = [], pos + 1
            while cursor < end:
                value, cursor = read(cursor)
                values.append(value)
            if cursor != end:
                raise ValueError("invalid list length")
            return values, end
        length_size = prefix - 0xf7
        end_len = pos + 1 + length_size
        if end_len > len(data):
            raise ValueError("truncated long list length")
        length = int.from_bytes(data[pos + 1:end_len], "big")
        if length < 56 or (length_size > 1 and data[pos + 1] == 0):
            raise ValueError("non-canonical long list")
        end = end_len + length
        if end > len(data):
            raise ValueError("truncated long list")
        values, cursor = [], end_len
        while cursor < end:
            value, cursor = read(cursor)
            values.append(value)
        if cursor != end:
            raise ValueError("invalid long list length")
        return values, end
    value, end = read(0)
    if end != len(data):
        raise ValueError("trailing RLP bytes")
    return value


def hex_bytes(value):
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ValueError("expected a 0x-prefixed hex value")
    text = value[2:]
    if len(text) % 2:
        text = "0" + text
    return bytes.fromhex(text)


def int_to_bytes(value):
    return b"" if value == 0 else value.to_bytes((value.bit_length() + 7) // 8, "big")


def quantity(value):
    return int(value, 16) if isinstance(value, str) else int(value)


def nibbles(data):
    result = []
    for byte in data:
        result.extend((byte >> 4, byte & 15))
    return result


def compact_decode(encoded):
    if not encoded:
        raise ValueError("empty compact path")
    raw = nibbles(encoded)
    flags = raw[0]
    if flags & 1:
        path = raw[1:]
    else:
        if raw[1] != 0:
            raise ValueError("invalid compact path padding")
        path = raw[2:]
    if flags >> 2:
        raise ValueError("invalid compact path flags")
    return path, bool(flags & 2)


def node_reference(node):
    if isinstance(node, bytes):
        if len(node) == 0:
            return None
        if len(node) == 32:
            return ("hash", node)
        return ("inline", node)
    raise ValueError("invalid trie child reference")


def proof_lookup(key, proof_nodes, root):
    """Return the RLP value at key, or None for a valid absence proof."""
    encoded_nodes = [hex_bytes(node) if isinstance(node, str) else node for node in proof_nodes]
    by_hash = {keccak256(node): node for node in encoded_nodes}
    current = ("hash", root)
    path = nibbles(key)
    offset = 0
    used = set()
    while current is not None:
        kind, ref = current
        if kind == "hash":
            encoded = by_hash.get(ref)
            if encoded is None:
                raise ValueError("proof is missing node %s" % ref.hex())
        else:
            encoded = ref
        marker = (kind, ref)
        if marker in used:
            raise ValueError("cycle in proof")
        used.add(marker)
        node = rlp_decode(encoded)
        if not isinstance(node, list):
            raise ValueError("trie node is not an RLP list")
        if len(node) == 17:
            if offset == len(path):
                return node[16]
            current = node_reference(node[path[offset]])
            offset += 1
            continue
        if len(node) != 2 or not isinstance(node[0], bytes):
            raise ValueError("invalid trie node shape")
        node_path, leaf = compact_decode(node[0])
        if path[offset:offset + len(node_path)] != node_path:
            return None
        offset += len(node_path)
        if leaf:
            return node[1] if offset == len(path) else None
        current = node_reference(node[1])
    return None


def account_from_proof(address, proof, state_root):
    value = proof_lookup(keccak256(hex_bytes(address)), proof, hex_bytes(state_root))
    if value is None:
        return None
    decoded = rlp_decode(value)
    if not isinstance(decoded, list) or len(decoded) != 4 or not all(isinstance(x, bytes) for x in decoded):
        raise ValueError("account leaf is not [nonce,balance,storageRoot,codeHash]")
    return {
        "nonce": int.from_bytes(decoded[0], "big"),
        "balance": int.from_bytes(decoded[1], "big"),
        "storageRoot": "0x" + decoded[2].hex(),
        "codeHash": "0x" + decoded[3].hex(),
    }


def storage_from_proof(slot, proof, storage_root):
    slot_bytes = hex_bytes(slot)
    if len(slot_bytes) > 32:
        raise ValueError("storage slot exceeds 32 bytes")
    # Solidity storage keys are 32-byte words before they are hashed into the trie.
    slot_bytes = b"\x00" * (32 - len(slot_bytes)) + slot_bytes
    value = proof_lookup(keccak256(slot_bytes), proof, hex_bytes(storage_root))
    if value is None or value == b"":
        return 0
    decoded = rlp_decode(value)
    if not isinstance(decoded, bytes):
        raise ValueError("storage leaf is not a byte string")
    return int.from_bytes(decoded, "big")


def verify_proof(block, proof):
    address = proof["address"]
    account = account_from_proof(address, proof["accountProof"], block["stateRoot"])
    if account is None:
        return {"address": address, "accountExists": False, "storage": [], "ok": True}
    expected_account = {
        "nonce": quantity(proof["nonce"]),
        "balance": quantity(proof["balance"]),
        "storageRoot": proof["storageHash"].lower(),
        "codeHash": proof["codeHash"].lower(),
    }
    account_ok = account == expected_account
    storage_results = []
    for entry in proof.get("storageProof", []):
        computed = storage_from_proof(entry["key"], entry["proof"], account["storageRoot"])
        expected = quantity(entry["value"])
        storage_results.append({"key": entry["key"], "value": expected, "computed": computed, "ok": computed == expected})
    return {"address": address, "accountExists": True, "account": account, "accountFieldsMatch": account_ok,
            "storage": storage_results, "ok": account_ok and all(item["ok"] for item in storage_results)}


class RpcError(RuntimeError):
    pass


class RpcClient:
    def __init__(self, url):
        self.url = url
        self.next_id = 1

    def call(self, method, params):
        request = Request(self.url, data=json.dumps({"jsonrpc": "2.0", "id": self.next_id,
                                                       "method": method, "params": params}).encode(),
                          headers={"content-type": "application/json", "User-Agent": "evm-state-proof-auditor/1.0"})
        self.next_id += 1
        try:
            with urlopen(request, timeout=30) as response:
                payload = json.load(response)
        except (HTTPError, URLError, TimeoutError) as exc:
            raise RpcError(str(exc)) from exc
        if payload.get("error"):
            raise RpcError(payload["error"].get("message", "JSON-RPC error"))
        return payload.get("result")


def block_tag(value):
    if value in ("latest", "earliest", "pending", "safe", "finalized") or value.startswith("0x"):
        return value
    return hex(int(value, 10))


def run(url, address, block_ref, slots):
    rpc = RpcClient(url)
    block = rpc.call("eth_getBlockByNumber", [block_tag(block_ref), False])
    proof = rpc.call("eth_getProof", [address, slots, block_tag(block_ref)])
    return verify_proof(block, proof)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Verify EVM account and storage proofs against a block stateRoot")
    parser.add_argument("rpc_url")
    parser.add_argument("address")
    parser.add_argument("block", help="block number, 0x quantity, or latest/finalized")
    parser.add_argument("slots", nargs="*", help="storage slots as 0x quantities")
    parser.add_argument("--json", action="store_true", help="print the full JSON result")
    args = parser.parse_args(argv)
    try:
        result = run(args.rpc_url, args.address, args.block, args.slots)
    except (RpcError, ValueError, KeyError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("address %s" % result["address"])
        print("account: %s" % ("PASS" if result["accountExists"] and result["accountFieldsMatch"] else "ABSENT"))
        for item in result["storage"]:
            print("slot %s: %s" % (item["key"], "PASS" if item["ok"] else "FAIL"))
        print("overall: %s" % ("PASS" if result["ok"] else "FAIL"))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
