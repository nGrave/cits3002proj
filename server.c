/*
SSL SERVER FOR CITS3002 Project 2016


Authors: Nathan Graves 21256779
         Daniel Cocks  
         Viktor Fidanovski

Compile on mac with:
gcc -o server server.c -Wall -lssl -lcrypto -lpthread -lm


TODO - 



*/

#include <ctype.h>
#include "openssl/ssl.h"
#include "openssl/bio.h"
#include "openssl/err.h"
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <dirent.h>
#include <assert.h>


#define OLDTRUSTY "OldTrusty/"
#define Certs "OldTrusty/ServerCerts/"
#define PRIV "OldTrusty/Priv/"

#define MAX_CONNECTIONS 10
#define MAX_ARGS 5 //from client

//Structure Vouching Linked List Structure
typedef struct _listnode {
	int item;
	struct _listnode *next;
} ListNode;

typedef struct _linkedlist {
	ListNode *head;
	int size;
} LinkedList;

typedef struct _vouchnode{
	char* fileName;
	//int item;
	LinkedList Vouchers;
	struct _vouchnode *next;
	//struct Vouchlist *head;
}VouchNode;

typedef struct _vouchlist {
	VouchNode *head;
	int size;
} VouchList;

VouchList Vouch;

//Declaration of function for use in addfile
int appendVouchNode(VouchList *vl, char* value);
//VouchNode * findVouchNode(VouchList *vl, int index);
VouchNode * findVouchNode(VouchList *vl, char* fileName, VouchNode** pre);
int removeVouchNode(VouchList *vl, VouchNode *cur, VouchNode *pre);


/*///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                   SOCK SETUP            - Ref Beej Networking Guide                                                                                 Returns A Bounded Listening Socked Descriptor
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////*/

int sock_setup(char* PORT){

    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage;    
    int yes=1;
    int rv;

    
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

        if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and bind to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("server: socket");
            continue;
        }

        //Re-Use Port
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
                sizeof(int)) == -1) {
            perror("setsockopt");
            exit(1);
        }

        //Binding
        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("server: bind");
            exit(1);
        }

        break;
    }

    freeaddrinfo(servinfo); // all done with this structure

    if (p == NULL)  {
        fprintf(stderr, "server: failed to bind\n");
        exit(1);
    }

    if (listen(sockfd, MAX_CONNECTIONS) == -1) {
        perror("listen");
        exit(1);
    }

    return sockfd;
}



/*///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                   Initialize SSL                                                                                                                     Return a pointer to a newly created SSL_CTX context
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////*/
SSL_CTX* InitSSL()
{
    SSL_CTX *ctx;
    SSL_load_error_strings();
    SSL_library_init();

     /* Set up the SSL context */

    //TODO SSLv23_server_method() for compatability or not needed as we are writing
    // a client pair for this server ???? ie both could just use SSLv3_server_ method() &&	SSLv3_client_ method() respectivly
     ctx = SSL_CTX_new(SSLv23_server_method());
     if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

     //require peer certificates
   


    SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
     
    /* Cannot fail ??? */
    SSL_CTX_set_verify_depth(ctx, 4);

     return ctx;
    

}

/*///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                         HANDLES RUNAWAY CHILDREN -Unused ATM From Beej                                         
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////*/

void sigchld_handler(int s)
{
    // waitpid() might overwrite errno, so we save and restore it:
    int saved_errno = errno;
    while(waitpid(-1, NULL, WNOHANG) > 0);
    errno = saved_errno;
}

/*///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                    Load SSL Certificates Into the SSL_CTX Context                                                  
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////*/


//PASS SSL_CTX* , CERTFILE, AND KEYFILE
void load_Certs(SSL_CTX* ctx, char* Cert, char* Key)
{
    // Set Certificate
    if ( SSL_CTX_use_certificate_file(ctx, Cert, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
   
    //Set Private key from keyfile -NOTE Possible same as certfile
    if ( SSL_CTX_use_PrivateKey_file(ctx, Key, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    //Verifiy private key ?? needed?
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

/*///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                   PRINTS CERTIFICATE INFORMATION    
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////*/

void ShowCerts(SSL* ssl)
{      char *line;
 
  X509 *cert = SSL_get_peer_certificate(ssl); 
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }


    else
        printf("Server: No Certificate Recieved from Client .. \n");
}
//Send all function uses structure and variables from Beej socket programming guide
int sendall(SSL* ssl, char *buf, int *len)
{
    int total = 0;        // how many bytes we've sent
    int bytesleft = *len; // how many we have left to send
    int n;

    while(total < *len) {
        n = SSL_write(ssl, buf+total, bytesleft);
        if (n == -1) { break; }
        total += n;
        bytesleft -= n;
    }

    *len = total; // return number actually sent here

    return n==-1?-1:0; // return -1 on failure, 0 on success
} 
////////////////////////////////////////////////////////////////////////////////////////////////
//                        List All 
//              -TODO SEND DOWN SSL TO CLIENT at the moment just list them in the server client
////////////////////////////////////////////////////////////////////////////////////////////////
int listAll(SSL* ssl)
{


DIR *dir;
struct dirent *ent;
if ((dir = opendir ("OldTrusty")) != NULL) {
  /* print all the files and directories within directory */
  while ((ent = readdir (dir)) != NULL) {
    printf ("%s\n", ent->d_name);
  }
  closedir (dir);
} else {
  /* could not open directory */
  perror ("");
  return EXIT_FAILURE;
}

/*
Expectation of client in this function
->Client sends prompt->Client Receives ok response
->Client Prepares to receive a int or long indicating how long the string is going to receive is(see send file process for this)
->Client recv until all that amount of bytes has been received and put into a string
->Client sends prompt that it has completed the transfer
String should be list of files with associated security information (probably not certs on server)
Each list item should be serperated by a ':' however if we need to this can be changed in python client
To do this change listoffiles.split(':') to a different character.
*/


return 0;
}
///CHECK IF A FILE EXISTS IN OLDTRUSTY/////////////////////////////
int checkFile (char *filename, int flag)
{
    
    char *pth ;
    //Concat OT directory and filename
  if(flag == 0){
  pth = malloc(strlen(OLDTRUSTY) + strlen(filename) +2 ); 
  sprintf(pth, "%s%s", OLDTRUSTY, filename);
  }

  if(flag == 1){
  pth = malloc(strlen(PRIV) + strlen(filename) +2 ); 
  sprintf(pth, "%s%s", PRIV, filename);
  }


  //check if file exists in directory
  struct stat   file;   
  int res = stat(pth, &file);
  //free memory allocation
  
  printf("Server: Path: %s\n" , pth);
  free(pth); 
  return res == 0;
}
////////////////////////////////////////////////////////////////////////////////////////////////
//                  -a addFile file to server on request first sending file length       
//                  //TODO
////////////////////////////////////////////////////////////////////////////////////////////////
int addFile(char* fileName, SSL* ssl  )
{
    char buffer[1024];//set up array to read bytes into
    int bytes;//variable for tracking how many bytes are received in each communication
    char response[] = "ok";//response for indicating to the client that the add file command was received successfully

     
   
    //Dont allow clients to overwrite files ?? 
    if(checkFile(fileName,0)){
        printf("Server: client trying to upload a file that Already exists in server\n");
        return -1;//TODO handle in client
    }

    SSL_write(ssl, response, strlen(response));//Send response to client indicating that next step can begin
    bytes = SSL_read(ssl,buffer,sizeof(buffer));//Reads from socket for next message
    while(bytes<=0){
        bytes = SSL_read(ssl,buffer,sizeof(buffer));
    }

    int bytestoreceive = atoi(buffer);//Convert message from buffer into an int representing the size of a file
    printf("Serer: Bytes to receive: %d\n", bytestoreceive);//Print the size of file
    fflush(stdout);


    SSL_write(ssl, response, strlen(response));//Send response to client indicating that the server is ready for next step
    // read in header first (long filesize, char* filename)
    FILE *filereceived;//Pointer to a file which the file to be received will be written to
    
    //Concat directory and filename
    char *pth = malloc(strlen(OLDTRUSTY) + strlen(fileName) +2 ); 
    sprintf(pth, "%s%s", OLDTRUSTY, fileName);

    filereceived=fopen(pth, "w+");//Create and open the file ready for writing
    free(pth);//free allocated memory

    int bytesreceieved =SSL_read(ssl,buffer,sizeof(buffer));//Track how many bytes received initially and will track through transfer
    fwrite(buffer, sizeof(buffer[0]), bytesreceieved, filereceived);//Write contents of first read to file

	//Remove entry in Linked list if overwriting another file
	VouchNode *temp,*pre;
	if ((temp = findVouchNode(&Vouch,fileName,&pre)) != NULL ){
				printf("\nSHOULD REMOVE NOW\n");
				printf("%s",temp->fileName);
				removeVouchNode(&Vouch, temp,pre);

	}
	
		//Append the file data to end of linked list
	fflush(stdout);
	if (appendVouchNode(&Vouch, fileName) == -1){
		printf("FAILED TO APPEND TO VOUCH");
	}
	
	printf("Successfully appended to end of list %s\n", findVouchNode(&Vouch, fileName, &pre)->fileName );
	
    while(bytesreceieved<bytestoreceive){//Check if all necessary bytes have been received
      //If not read again and update bytes received.
      bytesreceieved+=SSL_read(ssl,buffer,sizeof(buffer));
      fwrite(buffer, sizeof(buffer[0]), sizeof(buffer)/sizeof(buffer[0]), filereceived);//Write anything received to file
      printf("\r%i/%i",bytesreceieved, bytestoreceive);
      fflush(stdout);
    }
    fclose(filereceived);//Close the file once has finished
    SSL_write(ssl, response, strlen(response));//Send response to client that transfer is complete

    //Possibly add timeout function to this during reading while loop


return 0;

}

////////////////////////////////////////////////////////////////////////////////////////////////
//                  -f Send file to client on request first sending file length               //
////////////////////////////////////////////////////////////////////////////////////////////////
int sendFile(char* filename , SSL* ssl)
{
    long fileSize;
    FILE *fp;
    char buffer[1024];
    int bytes;

    char response[] = "ok";//response for indicating to the client that the add file command was received successfully

    //Check if the server contains the requested file.
    if(checkFile(filename,0) ) {
    printf("Server: Requested file exists in server attempting to send....\n");
    SSL_write(ssl, response, strlen(response));//Send response to client indicating that next step can begin
    }
    else{
        printf("Server: Requested file can not be found in server\n");
        SSL_write(ssl, "err", strlen("response"));//Send response to client indicating failure fie nto found
        return -1;
    }
    
    bytes = SSL_read(ssl,buffer,sizeof(buffer));//Reads from socket for next message which is circle length
    while(bytes<=0){
        bytes = SSL_read(ssl,buffer,sizeof(buffer));
    }

    int circlelength = atoi(buffer);    //store required circle length
    SSL_write(ssl, response, strlen(response));  //ok, next msg please

    bytes = SSL_read(ssl,buffer,sizeof(buffer));//Reads from socket hoping for name of person in trust chain
    while(bytes<=0){
        bytes = SSL_read(ssl,buffer,sizeof(buffer));
    }
    char requiredname[1024];
    strncpy(requiredname, buffer, sizeof(buffer));

    SSL_write(ssl, response, strlen(response));   //Got the required name 
   
    printf("Server: Required Security - Circle Length:%d Including Name: %s\n",circlelength, requiredname );
    
    //Concat directory and filename
    char *sndpth = malloc(strlen(OLDTRUSTY) + strlen(filename) +2 ); 
    sprintf(sndpth, "%s%s", OLDTRUSTY, filename);


    fp = fopen(sndpth, "rb");   //try to open required file
    
    if (fp == NULL) {
       printf("Server: Error Opening Client Requested File\n");
       return -1;
   }
    
      
  struct stat st;//structure for the size of a file
  stat(sndpth, &st);//using stat function to find details of filename
  fileSize = st.st_size;//storing for later use

  free(sndpth);

  printf("Server:  Size of file %ld\nServer: Sending file in progress please wait\n", fileSize);//Print out size of file
  fflush(stdout);
  const int n = snprintf(NULL, 0, "%lu", fileSize);//Stackover flow code for conversion of long to string
  assert(n > 0);
  char buf[n+1];
  int c = snprintf(buf, n+1, "%lu", fileSize);
  assert(buf[n] == '\0');
  assert(c == n);
  int lengthofstring = strlen(buf);//Length of string from long
  sendall(ssl, buf, &lengthofstring);//Send long string over socket to client
  int total=0;
  char sendbuffer[1024];//initialise send buffer
  int read = fread(sendbuffer, 1, sizeof(sendbuffer), fp);//read from file
  while(read==1024){//while read fills buffer
    sendall(ssl,sendbuffer,&read);//send entire buffer
    read = fread(sendbuffer, 1, sizeof(sendbuffer), fp);//read to buffer
    total += 1024 ;
    printf("\r%i of %li", total,fileSize);
    fflush(stdout);

  }
  sendall(ssl,sendbuffer,&read);//if buffer not filled send amount filled
  printf("\r%i of %li  bytes sent.",total + read, fileSize);//Indicates size of final read
  fflush(stdout);

  bytes = SSL_read(ssl,buffer,sizeof(buffer));//Reads from socket for finish
    while(bytes<=0){
        bytes = SSL_read(ssl,buffer,sizeof(buffer));
    }

    printf("\nServer: File Send OK\n");
 
  return 0; 

}
    
/*
Function for adding cert to server. Currently the same as adding a file
Should probably put them in the protected folder
*/

int addCert(char* fileName, SSL* ssl  )
{
    char buffer[1024];//set up array to read bytes into
    int bytes;//variable for tracking how many bytes are received in each communication
    char response[] = "ok";//response for indicating to the client that the add file command was received successfully
    SSL_write(ssl, response, strlen(response));//Send response to client indicating that next step can begin
    bytes = SSL_read(ssl,buffer,sizeof(buffer));//Reads from socket for next message
    while(bytes<=0){
        bytes = SSL_read(ssl,buffer,sizeof(buffer));
    }

    int bytestoreceive = atoi(buffer);//Convert message from buffer into an int representing the size of a file
    printf("Serer: Bytes to receive: %d\n", bytestoreceive);//Print the size of file
    fflush(stdout);


    SSL_write(ssl, response, strlen(response));//Send response to client indicating that the server is ready for next step
    // read in header first (long filesize, char* filename)
    FILE *filereceived;//Pointer to a file which the file to be received will be written to
   
       
    //Dont allow clients to overwrite files ?? 
    if(checkFile(fileName,1)){
        printf("Server: client trying to upload a certificate that Already exists in server\n");
        return -1;//TODO handle in client
    }

     //Concat directory and filename
    char *rpth = malloc(strlen(PRIV) + strlen(fileName) +2 ); 
    sprintf(rpth, "%s%s", PRIV, fileName);

    filereceived=fopen(rpth, "w+");//Create and open the file ready for writing.


    int bytesreceieved =SSL_read(ssl,buffer,sizeof(buffer));//Track how many bytes received initially and will track through transfer
    fwrite(buffer, sizeof(buffer[0]), bytesreceieved, filereceived);//Write contents of first read to file

    while(bytesreceieved<bytestoreceive){//Check if all necessary bytes have been received
      //If not read again and update bytes received.
      bytesreceieved+=SSL_read(ssl,buffer,sizeof(buffer));
      fwrite(buffer, sizeof(buffer[0]), sizeof(buffer)/sizeof(buffer[0]), filereceived);//Write anything received to file
    }
    fclose(filereceived);//Close the file once has finished
    SSL_write(ssl, response, strlen(response));//Send response to client that transfer is complete

    //Possibly add timeout function to this during reading while loop


return 0;

}

/*///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                  Processes Commands From the Client 
                                              -firts tokenize the string to work as commands
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////*/

int processCommand(char* str, SSL* ssl )
{

 char *cmd[10];
 int i = 0;
 char stcpy[5];


  cmd[i] =strtok(str," ");
  while (cmd[i] != NULL && i <10)
 {
   cmd[++i] =strtok(NULL, " ");
 }

    if (strcmp(cmd[0], "-a")== 0){
    printf("Server: Client would like to add %s file to the server.. : \n", cmd[1]);
    addFile(cmd[1] , ssl);
    }
                                          
    else if (strcmp(cmd[0], "-f")== 0){
    printf("Server: Client would like to fetch %s file from the server.. : \n", cmd[1]);
    if( sendFile(cmd[1] ,ssl) == -1 )
    printf("Server: Send Failed");
    }
    else if (strcmp(cmd[0], "-u")== 0){
    printf("Client would like to upload a certificate. : \n");
           addCert(cmd[1],ssl);                           }

    else if (strcmp(cmd[0], "-v")== 0){
    printf("Client would like to Vouch for  file: %s on the server.. : \n", cmd[1]);
    //vouchforfile(FileName, certificate);
    }

    else if (strcmp(cmd[0], "-h")== 0){
    printf("HostName: PortNumber: %s \n", cmd[1]);
    }

    else if (strcmp(cmd[0], "-l")== 0){
    printf("List Files.. \n");
    listAll(ssl);
    }

    else {
    return -1;
    }

    //HANDLE EXIT COMMAND --No Longer Needed?
    strncpy(stcpy, str, 4);
    stcpy[4] = '\0' ;
    if (strcmp(stcpy, "exit")== 0)
    return 9;

return 0;

}

/*///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                        SERVE CLIENT METHOD - TO BE CALLED BY CHILDREN                                                     
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////*/

void do_clients_bidding(SSL* ssl)
{
char buf[1024];
int  bytes;
char* welc_message = "Secure Connection to OLDTRUSTY File Server Established:";

//SEND WELCOME MESSAGE TO CLIENT
    SSL_write(ssl, welc_message , strlen(welc_message)); 

    bytes = SSL_read(ssl, buf, sizeof(buf));
    if ( bytes > 0 )
        {    
         buf[bytes] = 0;
            printf("Server Recieved From Client:  %s", buf); // Just echo the comman for tsting
           
            processCommand(buf,ssl);

        }
        else
            ERR_print_errors_fp(stderr);
    

printf("Server: Client all Done.Closing connection\nServer:  Awaiting New Connections\n");  //TODO track Clients (sequence numbers ?? close stuff down
 } 

/*///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                      Examine OldTrusty File Structure     
                                                 -Makes sure all folders are in the right place
                                                 -TODO security permissions for private folder??
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////*/
int checkFileStruct()
{
struct stat Ot = {0};
struct stat Sc = {0};
struct stat pr = {0};


if (stat("OldTrusty", &Ot) == -1) 
    return -1;
   

if (stat("OldTrusty/ServerCerts", &Sc) == -1) 
    return -1;

if (stat("OldTrusty/priv", &pr) == -1) 
    return -1;

  
 return 0;
}

/*///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                      Initialize VouchList     
                                                 -Makes sure "people" who vouch are remembered after server shutdown
                                                 -TODO Load from private (Very private plz) text file
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////*/


int initVouchStruct()
{
	
	Vouch.head = NULL;
	Vouch.size = 0;
	
	return 0;
	
	
}

/*///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                      Linked List Supporting Functions     
                                                 -Allows for manipulation of Linked lists
                                                 -TODO security permissions for private folder??
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////*/

//Finds requested node at index
ListNode * findNode(LinkedList *ll, int index)
{
	ListNode *temp;

	if (ll == NULL || index < 0 || index >= ll->size)
		return NULL;

	temp = ll->head;

	if (temp == NULL || index < 0)
		return NULL;

	while (index > 0) {
		temp = temp->next;
		if (temp == NULL)
			return NULL;
		index--;
	}

	return temp;
}

//Prints out List contents
void printList(LinkedList *ll)
{
	ListNode *cur;
	if (ll == NULL)
		return;
	cur = ll->head;
	if (cur == NULL)
		printf("Empty");
	while (cur != NULL)
	{
		printf("%d ", cur->item);
		cur = cur->next;
	}
	printf("\n");
}

//Clears Linked List
void removeAllItems(LinkedList *ll)
{
	ListNode *cur = ll->head;
	ListNode *tmp;

	while (cur != NULL) {
		tmp = cur->next;
		free(cur);
		cur = tmp;
	}
	ll->head = NULL;
	ll->size = 0;
}


//Removes node at specified index
int removeNode(LinkedList *ll, int index)
{
	ListNode *pre, *cur;

	// Highest index we can remove is size-1
	if (ll == NULL || index < 0 || index >= ll->size)
		return -1;

	// If removing first node, need to update head pointer
	if (index == 0) {
		cur = ll->head->next;
		free(ll->head);
		ll->head = cur;
		ll->size--;

		return 0;
	}

	// Find the nodes before and after the target position
	// Free the target node and reconnect the links
	if ((pre = findNode(ll, index - 1)) != NULL) {

		if (pre->next == NULL)
			return -1;

		cur = pre->next;
		pre->next = cur->next;
		free(cur);
		ll->size--;
		return 0;
	}
	return -1;
}

//Append ListNode
int appendNode(LinkedList *ll, int value)
{
	ListNode /**pre, */*cur;

	if (ll == NULL)
		return -1;

	// If empty list or inserting first node, need to update head pointer
	if (ll->head == NULL) {
		cur = ll->head;
		ll->head = malloc(sizeof(ListNode));
		ll->head->item = value;
		ll->head->next = cur;
		ll->size++;
		return 0;
	}
	/*
	// Find the nodes before and at the target position
	// Create a new node and reconnect the links
	if ((pre = findNode(ll, index - 1)) != NULL) {
		cur = pre->next;
		pre->next = malloc(sizeof(ListNode));
		pre->next->item = value;
		pre->next->next = cur;
		ll->size++;
		return 0;
	}
	*/
	return -1;
}

//Append VouchNode
int appendVouchNode(VouchList *vl, char* value)
{
	VouchNode *cur;

	if (vl == NULL /*|| value <= 0*/){
		printf("Could Not append Value");
		return -1;
	}

	// If empty list or inserting first node, need to update head pointer
	if (vl->size == 0) {
		printf("No head putting in first position, size = %d\n", vl->size);
		cur = vl->head;//NULL
		vl->head = malloc(sizeof(ListNode));
		vl->head->fileName = value;
		vl->head->next = cur;
		vl->size++;
		printf("SIZE = %d", vl->size);
		return 0;
	}
	
	
	// Find the nodes before and at the target position
	// Create a new node and reconnect the links

	while (cur->next != NULL) {
		cur = cur->next;
	}
			printf("Appending\n");
		cur->next = malloc(sizeof(ListNode));
		cur = cur->next;
		cur->fileName = value;
		cur->next = NULL;
		vl->size++;
		return 0;
	
}
/*
//Find VouchNode according to index
VouchNode * findVouchNode(VouchList *vl, int index)
{
	VouchNode *temp;

	if (vl == NULL || index >= vl->size)
		return NULL;

	temp = vl->head;

	if (temp == NULL || index < 0)
		return NULL;

	while (index > 0) {
		temp = temp->next;
		if (temp == NULL)
			return NULL;
		index--;
	}

	return temp;
}
*/
// find VouchNode according to filename
VouchNode * findVouchNode(VouchList *vl, char* fileName,VouchNode** pre)
{
	VouchNode *temp;

	temp = vl->head;

	if (temp == NULL /*|| fileName[0] == '\0' || vl == NULL*/){
		printf("RETURNING NULL 1");
		return NULL;
	}
	while (temp->next != NULL) {
		if( strcmp(fileName, temp->fileName) == 0 ){
			printf("RETURNING temp 1");
			return temp;
		}
			*pre = temp;
		temp = temp->next;
	}
	
	if(temp->next == NULL)
		if(strcmp(fileName,temp->fileName)==0){
			printf("Returing temp2");
			return temp;
	}
	printf("Returning Null 2");
	return NULL;
}

int removeVouchNode(VouchList *vl, VouchNode *cur, VouchNode *pre)
{
	// Highest index we can remove is size-1
	if (vl == NULL )
		return -1;

	// If removing first node, need to update head pointer
	if (cur == vl->head) {
		cur = vl->head->next;
		free(vl->head);
		vl->head = cur;
		vl->size--;

		return 0;
	}

	// Find the nodes before and after the target position
	// Free the target node and reconnect the links
		if (pre->next == NULL)
			return -1;

		pre->next = cur->next;
		free(cur);
		vl->size--;
		return 0;

}

/*///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                               ---------------------------- MAIN METHOD---------------------------------------                                                   
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////*/

int main(int argc , char *argv[])
{
    
     int sfd;
     char *P_num; 
     SSL_CTX * ctx;
     struct sockaddr_in cli_addr;   
     socklen_t len ;
     int cli;
     pid_t pid;
     struct sigaction sa;

    //Innitiliaze Server
   if (checkFileStruct() == -1){
       printf("Server: Problem With OldTrusty File Structure\n");
       exit(1);
   }
   //Initialize the Vouch Structure
       initVouchStruct();
   
    //Initialize SSL 
       
    if (argc != 2) {
        printf("Usage %s <portNUMBER> \n" , argv[0]);
        exit(1);
    }
    P_num = argv[1]; //Set Port

    ctx = InitSSL();
    load_Certs(ctx, "OldTrusty/ServerCerts/server.crt", "OldTrusty/ServerCerts/server.key");  //ALL IN ONE ? 
    //Get A regular tcp socket. already bound and listening.
    sfd = sock_setup(P_num);

    sa.sa_handler = sigchld_handler; // reap all dead processes
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
    perror("sigaction");
    exit(1); }
    

    printf("Server: OldTrusty Awaiting Connections on Port: %s\n" , P_num);

      //***********************************MAIN ACCEPT LOOP STARTS HERE *****************************/
    for(;;) {     
             
    len  = sizeof(cli_addr);
    
    cli = accept(sfd,  (struct sockaddr *)&cli_addr, &len); 
        if (cli == -1) {
            perror("accept");
            continue;
        }
    printf("Server: OLDTRUSTY recieved A Connection from: %s:%d\n",inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));

    SSL *ssl;

   
   if ( ( pid = fork())  == 0 ){

    //WE ARE THE CHILD
    close(sfd);    //Child doesnt need listner


    //Layer SSL Over Client Socket
    ssl = SSL_new(ctx); 
    SSL_set_fd(ssl, cli); 

  
    //HANDSHAKE.. 
    if ( SSL_accept(ssl) == -1)    
       ERR_print_errors_fp(stderr);

    //Show Client Certs (If any) // CAN ADDif require client auth then     //for now jsut show client certs if has any
    ShowCerts(ssl);

    // Here is a connection to the client 
    do_clients_bidding(ssl);
    
    SSL_free(ssl);
    close(cli);

    exit(0); // kill child.

    }  

    close(cli); //Parent closes connected socket (Being Handled in child)

    }  ///***END MAIN ACCEPT LOOP *****//
     
    SSL_CTX_free(ctx); //release context TODO never get hear?? graceful shutdown of server?
   
   
return 0;

}  

