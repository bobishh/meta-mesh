import tempfile
import unittest
from pathlib import Path
from export_graph import export, parse_value

class ExportTests(unittest.TestCase):
    def test_nested_tlc_values(self):
        self.assertEqual(parse_value('(r1 :> {<<1, alice>>, <<2, bob>>} @@ r2 :> {})'),
                         {'r1': [[1, 'alice'], [2, 'bob']], 'r2': []})
        self.assertEqual(parse_value('FALSE'), False)

    def test_unknown_value_fails_closed(self):
        with self.assertRaises(ValueError):
            parse_value('[x |-> 1]')
        with self.assertRaises(ValueError):
            parse_value('1 ignored')

    def test_unlabeled_edge_is_not_silently_omitted(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'graph.dot'
            path.write_text('1 -> 2 [color="black"];')
            with self.assertRaisesRegex(ValueError, 'Unsupported TLC graph'):
                export(path)

if __name__ == '__main__':
    unittest.main()
