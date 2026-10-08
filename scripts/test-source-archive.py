import importlib.util
from pathlib import Path
import tempfile
import unittest
import zipfile
spec = importlib.util.spec_from_file_location('source_archive', Path(__file__).with_name('source-archive.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class ArchiveTests(unittest.TestCase):
    def test_runtime_credentials_and_evidence_are_not_packaged(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)/'source'; root.mkdir()
            files = {'src/main.tsx':'source', 'src-tauri/src/core.rs':'source', 'src-tauri/tests/cli.rs':'test', 'src-tauri/examples/smoke.rs':'example',
                     '.github/workflows/check.yml':'workflow', 'docs/OS-MATRIX.md':'documentation', 'docs/CLI-VERIFICATION.md':'verification summary',
                     '.local/receipt.json':'SECRET', 'keys/api.key':'SECRET', '.env':'SECRET',
                     '.env.example':'SECRET', 'src/keys/key.ts':'SECRET', 'docs/evidence/runtime.md':'SECRET',
                     'docs/evidence/runtime.json':'SECRET', 'src-tauri/target/release/shugo':'SECRET',
                     'outputs/log.txt':'SECRET'}
            for name, data in files.items():
                p=root/name; p.parent.mkdir(parents=True,exist_ok=True); p.write_text(data)
            destination=Path(folder)/'source.zip'
            names=module.archive(root,destination)
            self.assertEqual(len(names),7)
            self.assertIn('docs/CLI-VERIFICATION.md',names)
            self.assertIn('src-tauri/examples/smoke.rs',names)
            with zipfile.ZipFile(destination) as z:
                self.assertFalse(any(b'SECRET' in z.read(name) for name in z.namelist()))
            with self.assertRaises(FileExistsError): module.archive(root,destination)
            self.assertTrue(destination.exists())
    def test_symlinked_allowed_source_is_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)/'source'; (root/'src').mkdir(parents=True)
            secret=Path(folder)/'secret'; secret.write_text('SECRET')
            try: (root/'src'/'main.tsx').symlink_to(secret)
            except OSError: self.skipTest('Host does not allow unprivileged symlinks')
            with self.assertRaises(ValueError): module.archive(root,Path(folder)/'source.zip')
            self.assertFalse((Path(folder)/'source.zip').exists())

if __name__=='__main__': unittest.main()
