# This is the client side code
# The client sends a query to the UID server
# Receives the Yes/No response from the UID server
# Verifies the message integrity and authenticates the server
# Repeats or terminates
import socket
import sys
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512

# Assume that user name, gender, phone, dob, email is in db

#Generate the pair of keys of client A using RSA
keyA = RSA.generate(1024)

#Write the public key of A into mykeyA.pem
f = open('mykeyA.pem','wb')

print(keyA.publickey().exportKey(format='PEM'))
public_keyA=keyA.publickey()
f.write(public_keyA.exportKey(format='PEM'))
f.close()

# create a socket object
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 

# get local machine name
host = socket.gethostname()                           

port = 9998

# connection to hostname on the port.
s.connect((host, port))     
                          
#send some data to the server
#message = 'This is the message.'
f = open('mykeyB.pem','r')
read_pub_keyB = RSA.importKey(f.read())
f.close()

query_stringA= raw_input('Enter your query (Enter 0 to stop) :\n')

# sample query string "1 Sid 4 80009000" where 1 means name and 4 means phone number

while (not(query_stringA == '0')) :
	enc_mssg=read_pub_keyB.encrypt(query_stringA.encode(),32)
	#print "Encry Mssg: %s" %enc_mssg
	hash1=SHA512.new(query_stringA.encode()).digest()
	#print "Hash1 %s" %hash1
	signatureA=keyA.sign(hash1,'')
	#print "SignaturA is %s" %signatureA

	#Separate the query and the signature with the delimiter '##'
	new_mssg=''.join(enc_mssg)+"##"
	new_mssg += str(signatureA)
	#print(type(new_mssg))
	#print "Sent msg %s" %new_mssg
	
	#Send to the server
	s.sendall(new_mssg) 

	# Receive response from server. No more than 2048 bytes
	resp = s.recv(2048)                                     
	#print "Length of response is %s" %len(resp)
	
	#Decrypt at client
	buf=""
		
	for i in range(len(resp)):
	 	if resp[i] == '#' and resp[i+1] == '#':
			#print "Breaking on getting double %s" %resp[i]						
			break
		else:
			buf += resp[i];
	new_mssg0 = buf;
	#print ("new_mssg0 has %s" % buf)		
	decr_mssg=keyA.decrypt(buf)
	print("\nDecrypted Response Msg: %s" %decr_mssg)

	buf=""
	for num in range(i+3,len(resp)):
		buf += resp[num]

#	print "\nBuffer has %s" %buf
	
	f = open('mykeyB.pem','r')
	read_pub_keyB = RSA.importKey(f.read())
	f.close()
	
	hash2=SHA512.new(decr_mssg).digest()
	new_mssg1 = ""
	for i in range(len(buf)):
 		if buf[i] == 'L':
			#print "Breaking on getting %s" %buf[i]				
			break
		else:				
			new_mssg1 += buf[i]
		
	#print "Received hash at client is %s" %new_mssg1
	
	#ensure that information is not altered during the 2-way communication between the client and server
	new_mssg1 = long(new_mssg1)
	integrity_A=read_pub_keyB.verify(hash2,(new_mssg1,))
	if(integrity_A == True):
		print("Signature of server is verified at client.")
	else:
		print("Signature of server at client is incorrect.")
	#-------------End of one query processing--------------
	query_stringA= raw_input('\nEnter your query (Enter 0 to stop) :\n')
	
s.close()