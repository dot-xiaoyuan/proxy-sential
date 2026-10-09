import importlib.util
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('frontend',Path(__file__).with_name('manage-frontend-previous.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class FrontendUpgradeReplay(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve()
        (self.root/'config').mkdir();(self.root/'releases').mkdir();self.state=self.root/'config/state.json';self.state.touch()
        self.a=self.release('a','A');self.b=self.release('b','B');self.c=self.release('c','B');self.d=self.release('d','C')
        (self.root/'current').symlink_to(self.b);(self.root/'previous').symlink_to(self.a)
    def release(self,name,graph):
        r=self.root/'releases'/name;p=r/'frontend/dist';(p/'assets').mkdir(parents=True)
        (p/'index.html').write_text('<html>'+graph+'</html>');(p/'assets'/('graph-'+graph+'.js')).write_text(graph)
        return r
    def test_backend_upgrade_retains_last_distinct_graph(self):
        m.prepare(self.root,self.c,self.state);self.assertEqual((self.root/'frontend-previous').resolve(),self.a)
        (self.root/'previous').unlink();(self.root/'previous').symlink_to(self.b)
        (self.root/'current').unlink();(self.root/'current').symlink_to(self.c)
        same=self.release('e','B');m.prepare(self.root,same,self.state)
        self.assertEqual((self.root/'frontend-previous').resolve(),self.a)
    def test_new_frontend_retains_current_and_rollback_restores_missing_pointer(self):
        m.prepare(self.root,self.d,self.state);self.assertEqual((self.root/'frontend-previous').resolve(),self.b)
        m.restore(self.root,self.state);self.assertFalse((self.root/'frontend-previous').exists())
    def test_rollback_restores_original_retained_graph(self):
        (self.root/'frontend-previous').symlink_to(self.a);m.prepare(self.root,self.d,self.state);m.restore(self.root,self.state)
        self.assertEqual((self.root/'frontend-previous').resolve(),self.a)
    def test_first_identical_graph_needs_no_retained_pointer(self):
        (self.root/'previous').unlink();(self.root/'previous').symlink_to(self.c)
        m.prepare(self.root,self.c,self.state);self.assertFalse((self.root/'frontend-previous').exists())
    def test_outside_release_and_unsafe_graph_rejected(self):
        outside=self.root/'outside';outside.mkdir()
        with self.assertRaises(ValueError):m.prepare(self.root,outside,self.state)
        (self.d/'frontend/dist/assets/unsafe').symlink_to(self.a/'frontend/dist/index.html')
        with self.assertRaises(ValueError):m.prepare(self.root,self.d,self.state)
        self.assertFalse((self.root/'frontend-previous').exists())
    def test_changed_pointer_is_not_overwritten_by_rollback(self):
        m.prepare(self.root,self.d,self.state)
        p=self.root/'frontend-previous';p.unlink();p.symlink_to(self.c)
        with self.assertRaises(ValueError):m.restore(self.root,self.state)
        self.assertEqual(p.resolve(),self.c)
    def test_tampered_state_and_symlink_state_rejected(self):
        m.prepare(self.root,self.d,self.state);self.state.write_text('{}')
        with self.assertRaises(ValueError):m.restore(self.root,self.state)
        self.state.unlink();self.state.symlink_to(self.a/'frontend/dist/index.html')
        with self.assertRaises(ValueError):m.prepare(self.root,self.d,self.state)

if __name__=='__main__':unittest.main()
