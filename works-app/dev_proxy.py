#!/usr/bin/env python3
"""本地联调代理：/works/ 提供静态前端，/works/api/ 转发到服务器 8790（经 ssh 隧道 8899）。"""
import http.server
import socketserver
import urllib.request
import urllib.error
import pathlib

DIST = pathlib.Path('/Users/zs/WorkBuddy/2026-10-31-01-46-49/works-app/dist')
UPSTREAM = 'http://127.0.0.1:8899/api/'


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *a):
        pass

    def do_GET(self):
        self.handle_any('GET', None)

    def do_POST(self):
        n = int(self.headers.get('Content-Length') or 0)
        self.handle_any('POST', self.rfile.read(n) if n else None)

    def handle_any(self, method, body):
        path = self.path.split('?')[0]

        if path.startswith('/works/api/'):
            sub = path[len('/works/api/'):]
            req = urllib.request.Request(UPSTREAM + sub, data=body, method=method)
            for h in ('Content-Type', 'Authorization'):
                if self.headers.get(h):
                    req.add_header(h, self.headers[h])
            try:
                with urllib.request.urlopen(req, timeout=30) as r:
                    data, status = r.read(), r.status
                    ctype = r.headers.get('Content-Type', 'application/json')
            except urllib.error.HTTPError as e:
                data, status = e.read(), e.code
                ctype = 'application/json'
            except Exception as e:  # noqa
                data, status, ctype = ('{"error":"%s"}' % e).encode(), 502, 'application/json'
            self.send_response(status)
            self.send_header('Content-Type', ctype)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        name = path.rstrip('/').split('/')[-1] or 'index.html'
        file = DIST / name
        if not file.is_file():
            file = DIST / 'index.html'
        data = file.read_bytes()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)


with socketserver.ThreadingTCPServer(('127.0.0.1', 8020), Handler) as httpd:
    httpd.allow_reuse_address = True
    print('proxy on http://127.0.0.1:8020/works/')
    httpd.serve_forever()
