/*
tested only on MacOSX 10.10.5 
Compile with 
gcc -o s s.c -Wall -lssl -lcrypto -lpthread -lm


        -Server shutdown commands / hotkeys ..callback function ? 
        -Track Clients to print out on server messages ??
        
        - Bugs- CMDs from client need a space after arguments ie.. "-f sample.text " instead of -f sample.txt


        - -listALL(ssl)
            -needs to send to client
            

        - addFile();
            -TODO
        
         - fetchFile() 
            -needs testing/fixing optimizing


            TODO-
        - circ() client ?
        - nameforTrust()
        - vouchFor()
        - upload cert()
        - remote adrr of server 

        -code cleanup.

 
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


#define MAX_CONNECTIONS 10
#define MAX_ARGS 5 //from client

/*///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                   SOCK SETUP                                                                                                                                  Returns A Bounded Listening Socked Descriptor
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
                                                                   Initialize SSL                                                                                                                              Return a pointer to a newly created SSL_CTX context

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
    return ctx;
    

}

/*///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                         HANDLES RUNAWAY CHILDREN                                                    
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
{   X509 *cert;
    char *line;
 
    cert = SSL_get_peer_certificate(ssl); 
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
        printf("No Certificate Recieved from Client .. \n Awaiting requests.....");
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


return 0;
}
////////////////////////////////////////////////////////////////////////////////////////////////
//                  -f Send file to client on request first sending file length       
//                  //TODO
////////////////////////////////////////////////////////////////////////////////////////////////
int addFile(char* fileName, SSL* ssl  )
{

// read in header first (long filesize, char* filename)




// while SSL_read < totalFileSize  keep reading --TIMEOUT ?? 



return 0;





}

////////////////////////////////////////////////////////////////////////////////////////////////
//                  -f Send file to client on request first sending file length               //
////////////////////////////////////////////////////////////////////////////////////////////////
int sendFile(char* filename , SSL* ssl)
{

  
    struct header {

    long data_length;
    //add other stuff here if needed?
    };


    char* buf;
    long fileSize;
    FILE *fp;
    
    //NOTE FOR TEAM stat() might be usefull to get info about fie (Owner last modified etc. permissions.)

    //Check if the server contains the requested file.
    if( access( filename , F_OK ) != -1 ) {
    printf("Server: Requested file exists in server attempting to send....\n ");

    } else {
        printf("Server: Requested file can not be found in server\n");
        return -1;
    }
    

   //attempt to open file
   fp = fopen(filename, "ab"); 

   if (fp == NULL) {
       printf("Server: Error Opening Client Requested File");
       return -1;
   }
    

// send file size to client.     
fseek(fp,0 ,SEEK_END);
fileSize =ftell(fp);
fseek(fp,0,SEEK_SET);

printf("the size of the req file is : %ld bytes \n " ,fileSize );
struct header hdr;
hdr.data_length = fileSize;

int ret = SSL_write(ssl, (char*)(&hdr) ,sizeof(hdr));

            
if (ret <=0)
{
SSL_get_error(ssl, ret);

}




//ALLOCATE MEMORY IN BUFFER
buf=(char *) malloc(fileSize + 1);
        if ( !buf){
        fprintf( stderr, "Memory Allocation Error");
        fclose(fp);
        }

fread(buf, fileSize , 1, fp);



//while SSL_write < filesize keep sending
//
long totalsent =0;

while ( totalsent < fileSize){

int sofar = SSL_write(ssl, buf ,sizeof(buf));
{
    if (sofar <=  0){
    SSL_get_error(ssl, ret);
    break; 
    }

    totalsent += sofar;
}

}

 printf("Server: File Sent %ld\n", totalsent ) ;


fclose(fp); //clsoe what we open.

//can shutdown here or stay open for ore commands
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



                //HANDLE COMMANDS .. PASS SSL TO SEPERATE METHODS IF NEEDED. PRINTF JUST FOR TESTING UNTIL METHODS ARE IMPLEMENTED

                            //HANDLE EXIT COMMAND...btw string manipulation in c is bullshit! :D
                             strncpy(stcpy, str, 4);
                             stcpy[4] = '\0' ;
                             if (strcmp(stcpy, "exit")== 0)
                             return 9;
                              
                   if       (strcmp(cmd[0], "-a")== 0){
                            printf("Server: Client would like to add %s file to the server.. : \n", cmd[1]);
                            addFile(cmd[1] , ssl);
                                         }
                   else if (strcmp(cmd[0], "-c")== 0){
                            printf("Server: Client requires circle of trust change....%s: \n", cmd[1]);
                            //setTrust();  -handle in client
                                          }
                   else if (strcmp(cmd[0], "-f")== 0){
                        printf("Server: Client would like to fetch %s file from the server.. : \n", cmd[1]);
                    if   ( sendFile(cmd[1] ,ssl) == -1 )
                        printf("Server: Send Failed");
                                         }
                   else if (strcmp(cmd[0], "-n")== 0){
                            printf("Circle of trust requires %s To be in the circle\n", cmd[1]);
                            //incNameintrust(char* name); --client?? 
                                         }
                   else if (strcmp(cmd[0], "-u")== 0){
                            printf("Client would like to upload a certificate. : \n");
                            //addCert();
                                         }
                   else if (strcmp(cmd[0], "-v")== 0){
                            printf("Client would like to Vouch for  file: %s on the server.. : \n", cmd[1]);
                           //vouchforfile(FileName, certificate);
                                         }
                   else if (strcmp(cmd[0], "-h")== 0){
                            printf("HostName: PortNumber: %s \n", cmd[1]);
                           //vouchforfile(FileName, certificate);
                                         }
                   else if (strcmp(cmd[0], "-l")== 0){
                            printf("List Files.. \n");
                            listAll(ssl);
                                                                    }


                   //Default Error Message (Non Supported Commands).
                   else {
                       return -1;
                         }
return 0;

}

/*///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                        SERVE CLIENT METHOD - TO BE CALLED BY CHILDREN                                                     
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////*/

void do_clients_bidding(SSL* ssl)
{
char buf[1024];
char rep[1024];
int  bytes;
char* welc_message = "Secure Connection to OLDTRUSTY File Server Established:\n";
char* cmdERR = "command error.\n";
bool exitcmd = false;

      //SEND WELCOME MESSAGE TO CLIENT
            sprintf(rep, welc_message , buf);   
            SSL_write(ssl, rep, strlen(rep)); 

    
  while (!exitcmd) {
    bytes = SSL_read(ssl, buf, sizeof(buf));
    if ( bytes > 0 )
        {    
            
            buf[bytes] = 0;
            printf("Recieved From Client:  %s", buf);
        
            int s =  processCommand(buf,ssl);

            if (s == 9) exitcmd = true;

            if (s == -1)
            {
             sprintf(rep, cmdERR , buf);  
             SSL_write(ssl, rep , strlen(rep));
              }

        }
        else
            ERR_print_errors_fp(stderr);
    
  }


printf("client exited, perform shutdown.....for client \n");  //TODO track Clients (sequence numbers ?? 
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

    //Innitiliaze Server
   if (checkFileStruct() == -1){
       printf("Problem With OldTrusty File Structure\n");
       exit(1);
   }
   



    //Initialize SSL 
       
    if (argc != 2) {
        printf("Usage %s <portNUMBER> \n" , argv[0]);
        exit(1);
    }
    P_num = argv[1]; //Set Port

    ctx = InitSSL();
    load_Certs(ctx, "OldTrusty/ServerCerts/mycert.pem", "OldTrusty/ServerCerts/mycert.pem");  //ALL IN ONE ? 
    //Get A regular tcp socket. already bound and listening.
    sfd = sock_setup(P_num);


    printf("OldTrusty Awaiting Connections on Port: %s\n" , P_num);

      //***********************************MAIN ACCEPT LOOP STARTS HERE *****************************/
    for(;;) {     
        //Ever ?? 
        
      len  = sizeof(cli_addr);
    
    cli = accept(sfd,  (struct sockaddr *)&cli_addr, &len); 
        if (cli == -1) {
            perror("accept");
            continue;
        }
    printf("OLDTRUSTY RECIEVED A Connection from: %s:%d\n",inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));

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

    //CREATE BIO OBJECT FOR THE SSL ?? TODO TO US OpenSSL over other channels (not just socketS)
    //TODO

    //Show Client Certs (If any) // CAN ADDif require client auth then -- check_cert(ssl,client )
    //for now jsut show client certs if has any
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
    
