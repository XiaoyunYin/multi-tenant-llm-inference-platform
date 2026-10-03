import unittest

import inference_platform


class PackageSmokeTest(unittest.TestCase):
    def test_version_is_exposed(self) -> None:
        self.assertEqual(inference_platform.__version__, "0.1.0")


if __name__ == "__main__":
    unittest.main()
