# This is the server side code
# The receives a query sent by the client in specified format
# Verifies the message integrity and authenticates the client
# Checks its database and sends the Yes/No response to the client
# Repeats or terminates
import socket                                         
import time
import datetime
import sys
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512

#Generate the pair of keys of server B using RSA
keyB = RSA.generate(1024)

#Write the public key of B into mykeyB.pem
f = open('mykeyB.pem','wb')
#print(keyB.publickey().exportKey(format='PEM'))
public_keyB=keyB.publickey()
f.write(public_keyB.exportKey(format='PEM'))
f.close()

# create a socket object
serversocket = socket.socket(
            socket.AF_INET, socket.SOCK_STREAM) 

# get local machine name
host = socket.gethostname()                           

port = 9998                                           

# bind to the port
serversocket.bind((host, port))                                  

# queue up to 5 requests
serversocket.listen(5)    
print "Server is listening..."                                       

while True:
    # establish a connection
    clientsocket,addr = serversocket.accept()      

    print("Got a connection from %s\n" % str(addr))

    try:
 
        # Receive the data in chunks of 2048 bytes
        while True:
            data = clientsocket.recv(2048)
	    if data:
                #print >>sys.stderr, 'received "%s"' % data
		#Decrypt at server
		buf=""
		
		for i in range(len(data)-1):
			if data[i] == '#' and data[i+1] == '#':
				break
			else:
				buf += data[i];
		new_mssg0 = buf;

		#print "new_mssg0 has %s" % buf		
		decr_mssg=keyB.decrypt(buf)
		print('Decrypted Query at server: %s' %decr_mssg)

		buf=""
		for num in range(i+3,len(data)):
			buf += data[num]
		#print len(data)-i-3
		#print "Buffer has %s" %buf
		
		f = open('mykeyA.pem','r')
		read_pub_keyA = RSA.importKey(f.read())
		f.close()
		hash2=SHA512.new(decr_mssg).digest()
		new_mssg1 = ""
		for i in range(len(buf)):
		 	if buf[i] == 'L':
				#print "Breaking on getting %s" %buf[i]				
				break
			else:				
				new_mssg1 += buf[i]
		
		#print "new_mssg1 has %s" %new_mssg1
		new_mssg1 = long(new_mssg1)
		integrity_B=read_pub_keyA.verify(hash2,(new_mssg1,))
		if(integrity_B == True):
			print("Signature of client is verified at the server")
		else:
			print("Signature of client at server is incorrect")

		# Test the query in your repository
		q1=(decr_mssg).decode("utf-8").split(" ")
		print "\nquery is %s" %q1
		
		#Database implementation to be done later
		#Testing with hardcoded data
		date1 = datetime.date(1989,3,1)
		date2 = datetime.date(1990,4,2)
		date3 = datetime.date(1991,4,2)
		records=[['10045',"LNClark",'M','1989-03-01','9999898989','lnc@iitd.ac.in'],['10046',"Simon",'M','1990-04-02','8999898989','simon@iitd.ac.in'],['10047','Sun','M','1991-04-02','7999898989','sun@iitd.ac.in']]

    	
		for rec in range(len(records)):
		        ans = 0
		        for vals in range(int(len(q1) / 2)):
		            idx = int(q1[vals * 2])		            
		            ans=ans + int(records[rec][idx]==q1[vals * 2 + 1])
		            
	        	if ans!=0 and ans==int(len(q1)/2):
		            #print("success")
		            break
	
		if (ans!=0 and ans==int(len(q1)/2)):
		    response='Yes'
		  
		else:
		    response = 'No'		
	
		response=response+" "+(decr_mssg).decode("utf-8")
		print("Resp is %s" %response)
		
		enc_mssg2=read_pub_keyA.encrypt(response.encode(),32)
		
		hash2=SHA512.new(response.encode()).digest()
		
		signatureB=keyB.sign(hash2,'')
		new_mssg_B_A=''.join(enc_mssg2)+"##"
		new_mssg_B_A += str(signatureB);
		
		#Send the response from B to A
		clientsocket.send(new_mssg_B_A)
	    else:
                break
            
            
    finally:
        # Clean up the connection
	    clientsocket.close()
