import os,sys,json,time
sys.path.insert(0,'/app')
import app
import smbclient
from unittest.mock import patch,Mock
cfg={'target':app.API,'tenant_id':'synthetic-tenant','token':'synthetic-token','share':r'\\fixture\fixtures','smb_user':'fixture','smb_password':os.environ['FIXTURE_PASSWORD'],'enabled':True}
app.save(cfg)
files=list(app.walk(cfg['share'],app.smb_options(cfg)))
assert len(files)==2,files
response=Mock(status_code=200)
response.json.return_value={'job_id':'synthetic-job'}
with patch.object(app.requests,'post',return_value=response) as post:
 for path in files:app.import_file(path,cfg)
 assert post.call_count==1,post.call_count
with app.connect() as c:
 assert c.execute('SELECT count(*) FROM sent').fetchone()[0]==1
 assert c.execute('SELECT count(*) FROM files').fetchone()[0]==2
assert b'synthetic-token' not in app.CONFIG.read_bytes()
print(json.dumps({'smb3_encrypted_read':'passed','recursive_files':len(files),'unique_upload_calls':1,'encrypted_config':'passed'}))
