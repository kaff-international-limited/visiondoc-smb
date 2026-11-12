import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch, Mock


class ApplianceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        os.environ['APPLIANCE_DATA'] = self.temp.name
        spec = importlib.util.spec_from_file_location('appliance_test', Path(__file__).parents[1] / 'app.py')
        self.a = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.a)
        self.client = self.a.app.test_client()

    def tearDown(self):
        self.temp.cleanup()

    def test_encrypted_settings_persist_and_cannot_cross_environments(self):
        self.a.save({'tenant_id': 'test', 'token': 'synthetic-token', 'smb_password': 'synthetic-password'})
        raw = self.a.CONFIG.read_bytes()
        self.assertNotIn(b'synthetic-token', raw)
        self.assertNotIn(b'synthetic-password', raw)
        self.assertEqual(self.a.config()['token'], 'synthetic-token')
        self.a.API = 'https://different.invalid/api'
        with self.assertRaises(RuntimeError):
            self.a.config()

    def test_csrf_login_guard_and_host_validation(self):
        self.assertEqual(self.client.post('/login', data={}).status_code, 403)
        self.assertEqual(self.client.get('/', headers={'Host': 'attacker.invalid'}).status_code, 400)
        self.assertEqual(self.client.get('/').status_code, 200)
        with self.client.session_transaction() as s:
            csrf = s['csrf']
        self.assertEqual(self.client.post('/share', data={'csrf': csrf}).status_code, 401)
        self.assertNotIn(b'synthetic-token', self.client.get('/').data)

    def test_company_password_is_exchanged_once_and_not_persisted(self):
        self.assertEqual(self.client.get('/').status_code, 200)
        with self.client.session_transaction() as session:
            csrf = session['csrf']
        cloud = Mock()
        cloud.__enter__ = Mock(return_value=cloud)
        cloud.__exit__ = Mock(return_value=False)
        signed_in = Mock(status_code=200)
        signed_in.json.return_value = {'tenant_id': 'fixture-company', 'permissions': ['settings:edit']}
        paired = Mock(status_code=200)
        paired.json.return_value = {'tenant_id': 'fixture-company', 'token': 'fixture-token', 'token_id': 'fixture-token-id'}
        cloud.post.side_effect = [signed_in, paired]
        with patch.object(self.a.requests, 'Session', return_value=cloud):
            response = self.client.post('/login', data={'csrf': csrf, 'email': 'admin@example.test', 'password': 'fixture-company-password'})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.a.config()['token'], 'fixture-token')
        self.assertNotIn('password', self.a.config())
        self.assertNotIn(b'fixture-company-password', self.a.FERNET.decrypt(self.a.CONFIG.read_bytes()))
        page = self.client.get('/')
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'Choose the folder', page.data)
        self.assertNotIn(b'fixture-token', page.data)

    def test_paths_reject_traversal(self):
        self.assertEqual(self.a.normalize_share('//nas/share/folder'), '\\\\nas\\share\\folder')
        for value in ['nas/share', '//nas/share/../other', '//nas', '//nas/share/']:
            with self.assertRaises(ValueError):
                self.a.normalize_share(value)

    def test_renamed_content_is_not_uploaded_twice(self):
        cfg = {'share': '\\\\nas\\share', 'smb_user': 'synthetic', 'smb_password': 'synthetic', 'token': 'synthetic'}
        stat = SimpleNamespace(st_size=7, st_mtime=1, st_mtime_ns=1000000000)
        import io
        response = Mock(status_code=200)
        response.json.return_value = {'job_id': 'synthetic-job'}
        with patch.object(self.a.smbclient, 'stat', return_value=stat), patch.object(self.a.smbclient, 'open_file', side_effect=lambda *a, **k: io.BytesIO(b'example')), patch.object(self.a.requests, 'post', return_value=response) as post:
            self.a.import_file('\\\\nas\\share\\first.txt', cfg)
            self.a.import_file('\\\\nas\\share\\renamed.txt', cfg)
        self.assertEqual(post.call_count, 1)
        with self.a.connect() as c:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM sent').fetchone()[0], 1)
            self.assertEqual(c.execute('SELECT COUNT(*) FROM files').fetchone()[0], 2)

    def test_lost_ack_does_not_mark_as_delivered(self):
        cfg = {'share': '\\\\nas\\share', 'smb_user': 'synthetic', 'smb_password': 'synthetic', 'token': 'synthetic'}
        stat = SimpleNamespace(st_size=7, st_mtime=1, st_mtime_ns=1000000000)
        import io
        with patch.object(self.a.smbclient, 'stat', return_value=stat), patch.object(self.a.smbclient, 'open_file', return_value=io.BytesIO(b'example')), patch.object(self.a.requests, 'post', side_effect=self.a.requests.Timeout):
            with self.assertRaises(self.a.requests.Timeout):
                self.a.import_file('\\\\nas\\share\\first.txt', cfg)
        with self.a.connect() as c:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM sent').fetchone()[0], 0)

    def test_changing_file_waits(self):
        cfg = {'share': '\\\\nas\\share', 'smb_user': 'synthetic', 'smb_password': 'synthetic', 'token': 'synthetic'}
        import io
        before = SimpleNamespace(st_size=7, st_mtime=1, st_mtime_ns=1000000000)
        after = SimpleNamespace(st_size=7, st_mtime=2, st_mtime_ns=2000000000)
        with patch.object(self.a.smbclient, 'stat', side_effect=[before, after]), patch.object(self.a.smbclient, 'open_file', return_value=io.BytesIO(b'example')), patch.object(self.a.requests, 'post') as post:
            self.a.import_file('\\\\nas\\share\\first.txt', cfg)
        post.assert_not_called()
        with self.a.connect() as c:
            self.assertEqual(c.execute('SELECT status FROM files').fetchone()[0], 'waiting')

    def test_folder_form_offers_encrypted_protocols(self):
        self.a.save({'tenant_id': 'fixture-company', 'token': 'synthetic-token', 'email': 'admin@example.test'})
        with self.client.session_transaction() as session:
            session['authenticated'] = True
            session['csrf'] = 'csrf-token'
        page = self.client.get('/')
        self.assertEqual(page.status_code, 200)
        body = page.data.decode()
        for label in ('>SMB<', '>SFTP<', '>FTPS<', '>WebDAV<'):
            self.assertIn(label, body)
        self.assertIn('Choose the folder', body)
        self.assertIn('Sign out', body)
        self.assertIn('64 MB', body)
        self.assertIn('#084050', body)
        self.assertIn('alt="VisionDoc"', body)
        self.assertIn('/static/brand/monogram-white-64.png', body)
        self.assertIn('data-brand="visiondoc" data-theme="light"', body)
        self.assertIn('color-scheme:light', body)
        self.assertNotIn('prefers-color-scheme: dark', body)
        self.assertNotIn('#e9f2ef', body)
        self.assertNotIn('#1e2a27', body)
        self.assertNotIn('Connect your company account to begin.', body)
        self.assertEqual(self.a.API, 'https://app.visiondoc.ai/api')
        from flask import session
        with self.a.app.test_request_context('/'):
            session['authenticated'] = True
            saved = self.a.render_template(
                'index.html',
                cfg={'email': 'admin@example.test', 'protocol': 'sftp', 'share': 'sftp://files.example/inbox'},
                files=[{'path': 'inbox/a.txt', 'bytes': 4, 'status': 'error', 'job_id': '', 'message': 'File exceeds the 64 MB upload limit and was not uploaded.'}],
                count=0, state={'running': False, 'message': 'Folder connected. Start importing when ready.', 'last_scan': None},
                csrf='csrf-token', error=None)
        self.assertIn('is-rejected', saved)
        self.assertIn('Failed', saved)
        self.assertIn('Start import', saved)
        self.assertIn('value="sftp" checked', saved)

    def test_remote_locations_reject_plaintext_and_traversal(self):
        self.assertEqual(self.a.normalize_location('sftp', 'sftp://files.example/inbox'), 'sftp://files.example/inbox')
        self.assertEqual(self.a.normalize_location('ftps', 'files.example/inbox'), 'ftps://files.example/inbox')
        self.assertEqual(self.a.normalize_location('webdav', 'https://files.example:8443/dav/inbox'), 'https://files.example:8443/dav/inbox')
        for protocol, raw in (
            ('sftp', 'sftp://files.example/inbox/../secret'),
            ('sftp', 'ftp://files.example/inbox'),
            ('sftp', 'sftp://user:secret@files.example/inbox'),
            ('ftps', 'ftp://files.example/inbox'),
            ('webdav', 'http://files.example/inbox'),
            ('webdav', 'https://files.example/inbox/'),
            ('sftp', 'sftp://files.example'),
            ('nfs', 'nfs://files.example/inbox'),
        ):
            with self.assertRaises(ValueError):
                self.a.normalize_location(protocol, raw)

    def test_unknown_protocol_is_not_saved(self):
        self.a.save({'tenant_id': 'fixture-company', 'token': 'synthetic-token', 'email': 'admin@example.test'})
        with self.client.session_transaction() as session:
            session['authenticated'] = True
            session['csrf'] = 'csrf-token'
        response = self.client.post('/share', data={'csrf': 'csrf-token', 'protocol': 'ftp', 'share': 'ftp://files.example/inbox', 'smb_user': 'reader', 'smb_password': 'synthetic'})
        self.assertEqual(response.status_code, 302)
        self.assertNotIn('share', self.a.config())
        page = self.client.get('/')
        self.assertIn(b'Choose SMB, SFTP, FTPS or WebDAV.', page.data)

    def test_webdav_listing_skips_the_folder_itself(self):
        payload = b'''<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"><d:response><d:href>/inbox</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop></d:propstat></d:response><d:response><d:href>/inbox/a.txt</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>4</d:getcontentlength><d:getlastmodified>Thu, 12 Nov 2026 00:00:00 GMT</d:getlastmodified></d:prop></d:propstat></d:response></d:multistatus>'''
        self.assertEqual(self.a.webdav_entries(payload, '/inbox'), [('/inbox/a.txt', 'file', '4', 'Thu, 12 Nov 2026 00:00:00 GMT')])

    def test_sftp_content_is_uploaded_once(self):
        import io
        cfg = {'protocol': 'sftp', 'share': 'sftp://files.example/inbox', 'token': 'synthetic', 'smb_user': 'reader', 'smb_password': 'synthetic'}

        class Fake:
            def stat(self, path):
                return self_a.RemoteStat(7, 1)
            def open(self, path):
                return io.BytesIO(b'example')
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False

        self_a = self.a
        response = Mock(status_code=200)
        response.json.return_value = {'job_id': 'synthetic-job'}
        with patch.object(self.a, 'remote_source', return_value=Fake()), patch.object(self.a.requests, 'post', return_value=response) as post:
            self.a.import_file('sftp://files.example/inbox/first.txt', cfg)
            self.a.import_file('sftp://files.example/inbox/renamed.txt', cfg)
        self.assertEqual(post.call_count, 1)
        with self.a.connect() as c:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM sent').fetchone()[0], 1)

    def test_oversized_file_is_not_uploaded(self):
        cfg = {'share': '\\\\nas\\share', 'smb_user': 'synthetic', 'smb_password': 'synthetic', 'token': 'synthetic'}
        stat = SimpleNamespace(st_size=self.a.MAX_BYTES + 1, st_mtime=1, st_mtime_ns=1_000_000_000)
        with patch.object(self.a.smbclient, 'stat', return_value=stat), patch.object(self.a.smbclient, 'open_file') as opened, patch.object(self.a.requests, 'post') as post:
            self.a.import_file('\\\\nas\\share\\big.pdf', cfg)
        opened.assert_not_called()
        post.assert_not_called()
        with self.a.connect() as c:
            row = c.execute('SELECT status, message FROM files').fetchone()
        self.assertEqual(row['status'], 'error')
        self.assertIn('64 MB', row['message'])
        self.assertIn('not uploaded', row['message'])

    def test_read_stops_before_an_oversized_body_is_uploaded(self):
        cfg = {'share': '\\\\nas\\share', 'smb_user': 'synthetic', 'smb_password': 'synthetic', 'token': 'synthetic'}
        stat = SimpleNamespace(st_size=7, st_mtime=1, st_mtime_ns=1_000_000_000)

        class Big:
            def read(self, _size):
                return b'x' * (limit + 1)
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False

        limit = self.a.MAX_BYTES
        with patch.object(self.a.smbclient, 'stat', return_value=stat), patch.object(self.a.smbclient, 'open_file', return_value=Big()), patch.object(self.a.requests, 'post') as post:
            self.a.import_file('\\\\nas\\share\\grew.pdf', cfg)
        post.assert_not_called()
        with self.a.connect() as c:
            self.assertEqual(c.execute('SELECT status FROM files').fetchone()['status'], 'error')

    def test_upload_limit_cannot_be_raised_above_64_mb(self):
        os.environ['MAX_FILE_BYTES'] = str(500 * 1024 * 1024)
        try:
            spec = importlib.util.spec_from_file_location('appliance_limit_high', Path(__file__).parents[1] / 'app.py')
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            self.assertEqual(module.MAX_BYTES, 64 * 1024 * 1024)
        finally:
            os.environ.pop('MAX_FILE_BYTES', None)


if __name__ == '__main__':
    unittest.main()
