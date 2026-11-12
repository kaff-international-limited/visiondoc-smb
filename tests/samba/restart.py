import sys,json
sys.path.insert(0,'/app')
import app
from unittest.mock import patch
cfg=app.config()
assert cfg['tenant_id']=='synthetic-tenant' and cfg['enabled']
with patch.object(app.requests,'post') as post:
 for path in app.walk(cfg['share'],app.smb_options(cfg)):app.import_file(path,cfg)
 post.assert_not_called()
print(json.dumps({'settings_restored_after_new_container':'passed','duplicate_uploads_after_restart':0}))
