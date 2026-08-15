# NEURAL-X Gunicorn Configuration
import multiprocessing

bind = "0.0.0.0:5000"
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "sync"
worker_connections = 1000
timeout = 120
keepalive = 5
max_requests = 1000
max_requests_jitter = 100
preload_app = True
accesslog = "logs/gunicorn-access.log"
errorlog  = "logs/gunicorn-error.log"
loglevel  = "info"
capture_output = True
