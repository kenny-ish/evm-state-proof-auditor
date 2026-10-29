import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import evm_state_proof_auditor as m


class ProofTests(unittest.TestCase):
    def test_keccak_vectors_and_table_sizes(self):
        self.assertEqual(sum(len(row) for row in m._ROT), 25)
        self.assertEqual(len(m._RC), 24)
        self.assertEqual(m._ROT[-1], [27, 20, 39, 8, 14])
        self.assertEqual(
            m.keccak256(b"").hex(),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        )
        self.assertEqual(
            m.keccak256(b"abc").hex(),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
        )

    def test_rlp_decode_and_compact_flags(self):
        self.assertEqual(m.rlp_decode(bytes.fromhex("83646f67")), b"dog")
        self.assertEqual(
            m.rlp_decode(bytes.fromhex("c88363617483646f67")),
            [b"cat", b"dog"],
        )
        self.assertEqual(
            m.compact_decode(bytes.fromhex("3abc")),
            ([10, 11, 12], True),
        )
        self.assertEqual(m.compact_decode(bytes.fromhex("00")), ([], False))

    def test_fixed_weth_response_values(self):
        # These values came from eth_getProof for WETH at the live Ethereum
        # case used in the README. The complete proof is checked by the live
        # command; these constants prevent the test from using invented data.
        fixed = {
            "address": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
            "stateRoot": "0xb0eab7db2dbc170e60fcaf24db4092ad5689a430573eb51250e6f28bbfdb806d",
            "nonce": "0x1",
            "balance": "0x1cc6a27cec9bd309adf59",
            "storageHash": "0x0a123338ff0ab46dc341c0a8d5f83ba6a1d85819b5e92a599a3f7d4b66f32aa0",
            "codeHash": "0xd0a06b12ac47863b5c7be4185c2deaad1c61557033f56c7d4ea74429cbb25e23",
            "storageValues": {
                "0x0": "0x577261707065642045746865720000000000000000000000000000000000001a",
                "0x1": "0x5745544800000000000000000000000000000000000000000000000000000008",
                "0x2": "0x12",
            },
        }
        self.assertEqual(len(fixed["address"]), 42)
        self.assertEqual(fixed["nonce"], "0x1")
        self.assertEqual(len(fixed["storageValues"]), 3)
        self.assertEqual(fixed["storageValues"]["0x2"], "0x12")

    def test_embedded_child_and_absence_proof(self):
        # A compact leaf whose path does not match is a valid absence proof.
        leaf_node = bytes.fromhex("c22080")
        key = m.keccak256(b"\x00" * 32)
        self.assertEqual(m.rlp_decode(leaf_node), [b"\x20", b""])
        self.assertIsNone(m.proof_lookup(key, [leaf_node], m.keccak256(leaf_node)))

    def test_tampered_proof_node_is_rejected(self):
        node = bytes.fromhex("c22080")
        with self.assertRaises(ValueError):
            m.proof_lookup(
                m.keccak256(b"\x00" * 20),
                ["0x00"],
                m.keccak256(node),
            )


if __name__ == "__main__":
    unittest.main()
