
import argparse
import socket
import ssl
import os
import time
from ipaddress import ip_address

sockettouse = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

securityrequirements = 0;
namerequirements = None;



def parse_arguments():#set up parsing of arguments for required arguements
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', nargs=1, type =str )
    parser.add_argument('-c', nargs=1)
    parser.add_argument('-f', nargs=1)
    parser.add_argument('-ho', nargs=1)
    parser.add_argument('-l', nargs=1)
    parser.add_argument('-n', nargs=1)
    parser.add_argument('-u', nargs=1)
    parser.add_argument('-v', nargs=2)
    args = parser.parse_args()
    return args




def connecttoserver(hostname,port):
    sockettouse.connect(hostname, port)
    return sockettouse



def sendPrompt(prompt,sslsocket):
    tosend = prompt.encode('utf-8')#build prompt to be sent.
    sslsocket.send(tosend)#send prompt over ssl

    data = sslsocket.recv(1024)#receive response

    while(data==[]):
        data = sslsocket.recv(1024)

    if data==tosend:
        return True;#if prompt accepted then mirror of prompt returned
    if data.decode('utf-8','strict') == 'ok': return True
    else: return False


def addFile(filename, sslsocket):
    print(filename)
    if os.path.isfile(filename)==False: 
        return print("File not uploaded. File not found")
    
    if sendPrompt('-a '+filename,sslsocket)==False:  #send the prompt, check if it is received
        return print("File not uploaded. Prompt not received correctly")
    size = os.path.getsize(filename) #determine size of the file
    if sendPrompt(str(size),sslsocket)==False:#send a file size prompt to the server
       return print("File not uploaded. Size Prompt not received correctly")

                   
    filetosend = open(filename, 'rb') #open the file to send
    sendbuffer = filetosend.read(1024) #read file into buffer
    while(sendbuffer):#while something gets read
        sent = sslsocket.send(sendbuffer)#send over sslsocket
        #print('Bytes Sent' + str(sent))#report bytes sent
        sendbuffer = filetosend.read(1024)#read the next part of file to send

    #here should wait for a server acknowledgement that transfer is complete

    data = sslsocket.recv(1024)#receive response

    while(data==[]):
        data = sslsocket.recv(1024)
    if data.decode('utf-8','ignore') == 'ok': return print("File Successfully Uploaded")

        

    return print('File not uploaded successfully')

def fetchFile(filename,trustlength,trustedperson, sslsocket):
    if sendPrompt('-f '+filename,sslsocket)==False: 
        return print("File not downloaded, prompt not received or file not found")#send the prompt to the server
    if sendPrompt(trustlength, sslsocket)==False:#sending the length of chain required to trust a file
        return print("Trust length prompt not received")
    if sendPrompt(trustedperson, sslsocket)==False:#sending the required person to be present in the chain
        return("Trusted person prompt not found or file not trusted.")

    sizeprompt = sslsocket.recv(1024)   #receive size of file that will be received
    print(sizeprompt.decode('utf-8','replace'))
    recievedfile = open(filename, 'wb') #create file on in root folder with specified name, prepared to be written to
    size = int.from_bytes(sizeprompt, byteorder='little')#convert size of file from byte array to int
    amountreceived = 0  #Variable for tracking how much has been received through the socket.
    receiveddata = sslsocket.recv(1024) #Receive first chunck of data from socket
    while amountreceived < size: #While all expected data of file has not been received keep looking for more
        recievedfile.write(receiveddata)
        amountreceived+=int.from_bytes(receiveddata , byteorder ='little')
        receiveddata=sslsocket.recv(1024)
    sendPrompt('complete',sslsocket)
    return 0



def listFiles(sslsocket):
    if sendPrompt('-l',sslsocket)==True: return 1 #send the prompt to the server
    sizeprompt = sslsocket.recv(1024) 
    size = sizeprompt.from_bytes(len(sizeprompt), 'little')
    receivedstring = [] #byte array where string will be copied to
    amountreceived = 0 #Track amount received from socket
    receiveddata = sslsocket.recv(1024) #Receive first part of data
    while amountreceived < size: #Receive until all expected data it received
        receivedstring.append(receiveddata) #Add received bytes to array
        amountreceived+=receiveddata.len #Update amount received
        receiveddata = sslsocket.recv(1024)
    sendprompt('complete', sslsocket) #Inform server that process is complete
    listoffiles=receivedstring.decode('utf-8', 'ignore') #Decode the received btye array into a usable string
    listitems = listoffiles.split(':') #Split string into list of different server files
    print('List of Items on Server with Protection') 
    for listitem in listitems:
        print(listitem) #Print list of items
    return 0

def uploadCertificate(certificatename, sslsocket):
    if sendPrompt('-u',sslsocket)==False:
        return print('Certificate not upleaded Send Prompt Not Received Correctly')
        
    if os.path.isfile(certificatename)==False: 
        return print("Certificate not uploaded. Certificate not found")
    size = os.path.getsize(filename) #determine size of the file
    if sendPrompt(size,sslsocket)==False:#send a file size prompt to the server
        return print("Certificate not uploaded. Size Prompt not received correctly")
    if sendPrompt(certificatename,sslsocket)==False:
        return print("Certificate not uploaded. Filename prompt not received correctly or certificate already exists")
                   
    certtosend = open(certificatename, 'rb') #open the file to send
    sendbuffer = certtosend.read(1024) #read file into buffer
    while(sendbuffer):#while something gets read
        sent = sslsocket.send(sendbuffer)#send over sslsocket
        print('Bytes Sent' + str(sent))#report bytes sent
        sendbuffer = certtosend.read(1024)#read the next part of certificate to send
    return 0

def verifyFile(signature, sslsocket):
    if sendPrompt('-a',sslsocket)==True: return 1

    #send the prompt to the server
    return 0

def main():
    arguments = parse_arguments()
    if arguments.ho is None:
        print("Please Specify a host")
        return
    ip, separator, port = arguments.ho[0].rpartition(':')
    assert separator # separator (`:`) must be present
    port = int(port) # convert to integer
    ip = ip_address(ip.strip("[]")) 
    print(ip)
    print(port)

    securityrequirements = 0;
    namerequirements = 'None';

    if arguments.c!=None:securityrequirements=arguments.c[0]
    if arguments.n!=None:namerequirements=arguments.n[0]

    print(securityrequirements)
    print(namerequirements)


    if arguments.a is None and arguments.f is None and arguments.l is None and arguments.u is None and arguments.v is None:
        print('Please specify an action')
        return

    sslsock = ssl.wrap_socket(sockettouse)
    sslsock.connect((str(ip), port))
    data = sslsock.recv(1024)
    print(data)
    if arguments.a is not None: addFile(arguments.a[0], sslsock)
    if arguments.f is not None: fetchFile(arguments.f[0],securityrequirements,namerequirements,sslsock)
    if arguments.l is not None: listFiles(sslsock)
    if arguments.u is not None: uploadCertificate(arguments.u[0],sslsock)
    #if arguments.v is not None: verifyFile(arguments.v,sslsock)
    sendPrompt('exit',sslsock)
    sslsock.close()



        
if __name__ == '__main__':
    main()







