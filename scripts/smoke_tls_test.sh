#!/bin/bash
pkill -f "ssl_listener_8443" 2>/dev/null
sleep 1
openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/cert.key -out /tmp/cert.crt -days 1 -subj "/CN=test" 2>/dev/null
nohup python3 -c "
# ssl_listener_8443
import http.server, ssl
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain('/tmp/cert.crt', '/tmp/cert.key')
s = http.server.HTTPServer(('127.0.0.1', 8443), http.server.SimpleHTTPRequestHandler)
s.socket = ctx.wrap_socket(s.socket, server_side=True)
s.serve_forever()
" > /tmp/listener.log 2>&1 &
echo $! > /tmp/listener.pid
sleep 3
cd /tmp/fastscan && timeout 90 ./fastscan -target 127.0.0.1 -ports 8443 -skip-nmap 2>&1 | tee /tmp/smoke2.log | grep -E "TLS upgraded|ssl. [0-9]+ targets|phase 3|phase 4|HIT|tls. [0-9]+ targets"
kill $(cat /tmp/listener.pid) 2>/dev/null
sleep 1
pkill -f "ssl_listener_8443" 2>/dev/null
rm -f /tmp/cert.crt /tmp/cert.key /tmp/listener.pid
echo "--listener gone--"
pgrep -fa "ssl_listener_8443" || echo "no listener procs"
