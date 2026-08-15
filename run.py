"""NEURAL-X Application Entry Point"""

import os
from app import create_app
<<<<<<< HEAD
=======
from app import db
>>>>>>> 99727748a15251a8f4d92432e4608bc61952b66f

app = create_app(os.getenv('FLASK_ENV', 'development'))

# Jinja2 extras
import json
from datetime import datetime

@app.template_filter('from_json')
def from_json_filter(value):
    try:
        return json.loads(value) if value else {}
    except Exception:
        return {}

@app.template_filter('truncate')
def truncate_filter(s, length=80):
    if not s:
        return ''
    s = str(s)
    return s if len(s) <= length else s[:length] + '…'

@app.context_processor
def inject_globals():
    return {'now': datetime.utcnow()}


<<<<<<< HEAD
=======

>>>>>>> 99727748a15251a8f4d92432e4608bc61952b66f
if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=int(os.getenv('PORT', 5000)),
        debug=os.getenv('FLASK_ENV', 'development') == 'development'
    )
<<<<<<< HEAD
=======

 
>>>>>>> 99727748a15251a8f4d92432e4608bc61952b66f
