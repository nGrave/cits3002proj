/*
tested only on MacOSX 10.10.5 
Compile with 
gcc -o s s.c -Wall -lssl -lcrypto -lpthread -lm
 */


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

#define MAX_CONNECTIONS 10
#define BACKLOG 10  

/**
 *  sock_setup
 *@return returns a listening bounded socket
 */
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

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
                sizeof(int)) == -1) {
            perror("setsockopt");
            exit(1);
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("server: bind");
            continue;
        }

        break;
    }

    freeaddrinfo(servinfo); // all done with this structure

    if (p == NULL)  {
        fprintf(stderr, "server: failed to bind\n");
        exit(1);
    }

    if (listen(sockfd, BACKLOG) == -1) {
        perror("listen");
        exit(1);
    }

    return sockfd;
}



// Setup SSL
SSL_CTX* InitSSL()
{
    SSL_CTX *ctx;
    ERR_load_BIO_strings();
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
//Close and clean up SSL
void cleanupSSL(SSL *s)
{
    SSL_shutdown(s);
    SSL_free(s);
}

//Destroy ?? SSL.
void DestroySSL()
{
     ERR_free_strings();
     EVP_cleanup();
}

// **FROM BEEJ ** -- Reaps Runaway Children..
void sigchld_handler(int s)
{
    // waitpid() might overwrite errno, so we save and restore it:
    int saved_errno = errno;
    while(waitpid(-1, NULL, WNOHANG) > 0);
    errno = saved_errno;
}

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

//DIRECT COPY AND PASTE FROM
// http://simplestcodings.blogspot.com.au/2010/08/secure-server-client-using-openssl-in-c.html
void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;
 
    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
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
        printf("No certificates.\n");
}

void do_clients_bidding(SSL* ssl)
{
char buf[1024];
char rep[1024];
int sd, bytes;
char* test_message = "OLDTRUSTY FTP SERVER....Testing secure connection \0";


// Do Certificaty stuff here .. new method req -- checkSec()
   if ( SSL_accept(ssl) == -1)     /* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);

    bytes = SSL_read(ssl, buf, sizeof(buf));
    if ( bytes > 0 )
        {
            buf[bytes] = 0;
            printf("Client msg: %s \n", buf);

            sprintf(rep, test_message , buf);   
            SSL_write(ssl, rep, strlen(rep));       
        }
        else
            ERR_print_errors_fp(stderr);
    

    sd = SSL_get_fd(ssl);       /* get socket connection */
    SSL_free(ssl);         /* release SSL state */
    close(sd);
}



int main(int argc , char *argv[])
{
     //BIO Object and ssl context object
     int sfd;
     char *P_num; 
     SSL_CTX * ctx;
     struct sockaddr_in cli_addr;
     socklen_t len ;
     int cli;

     

    //Initialize SSL 
       
    if (argc != 2) {
        printf("Usage %s <portNUMBER> \n" , argv[0]);
        exit(1);
    }
    P_num = argv[1]; //Set Port --TODO get rid fo pesky port still in use probs

    ctx = InitSSL();
    load_Certs(ctx, "mycert.pem", "mycert.pem");
    //Get A regular tcp socket. already bound and listening.
    sfd = sock_setup(P_num);


    printf("OldTrusty Awaiting Connections on Port: %s\n" , P_num);

    for(;;) { //Main accept loop
    len  = sizeof(cli_addr);
    SSL *ssl;

    cli = accept(sfd,  (struct sockaddr *)&cli_addr, &len); 
        if (cli == -1) {
            perror("accept");
            continue;
        }
    printf("We Have a Connection from: %s:%d\n",inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));
    
    ssl = SSL_new(ctx); 
    SSL_set_fd(ssl, cli); 

    // Here is a connection to the client 
    do_clients_bidding(ssl);
    
    }
     
   
close(sfd); //close socket
SSL_CTX_free(ctx); //release context
   
   
return 0;

}  
    
