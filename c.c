/*
tested only on MacOSX 10.10.5 
Compile with 
gcc -o c c.c -Wall -lssl -lcrypto -lpthread -lm

 */

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc/malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
 
#define FAIL    -1
 
int tcpConnect(const char *servName, int port)
{   int sd;
    struct hostent *host;
    struct sockaddr_in addr;
 
    if ( (host = gethostbyname(servName)) == NULL )
    {
        perror(servName);
        exit(1);
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        close(sd);
        perror(servName);
        exit(1);
    }
    return sd;
}
 
SSL_CTX* InitSSLctx()
{  
    SSL_CTX *ctx;
    

    //Init SSL 
    OpenSSL_add_all_algorithms(); 
    SSL_load_error_strings(); 
    SSL_library_init();



    // Probably use more secure TLSv1_2_client_method but issues on my mac 
     ctx = SSL_CTX_new(SSLv23_client_method());   
       
       
       if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    return ctx;
}
 
void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;
 
    //GET CERTS FROM SERVER
    cert = SSL_get_peer_certificate(ssl); 
   if (  SSL_get_verify_result(ssl) == X509_V_OK)
      printf("Server Check Ok....We can trust oldtrusty to be who he said he is.");

  else printf("WARNING..CERT VALIDATION FAILED...PROCEED WITH CAUTION");


  printf( SSL_get_verify_result(ssl));
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
        printf("Info: No client certificates configured.\n");

  

    //TODO -- CHECK IF VALID OR WE WANT TO CONTINUE HERE??? 
}
 
int main(int argc, char *argv[])
{   SSL_CTX *ctx;
    SSL *ssl;
       int bytes;
       int serv_fd;
       char buf[1024];
 

    char *hostname, *portnum;
 
    if ( argc != 3 )
    {
        printf("usage: %s [Host][ [Port]\n", argv[0]);
        exit(0);
    }

  
    hostname=argv[1];
    portnum=argv[2];
 
    //Setup Context
    ctx = InitSSLctx();
    //Get bounded Socket
    serv_fd = tcpConnect(hostname, atoi(portnum));
    
    ssl = SSL_new(ctx);

    //Wrap together 
    SSL_set_fd(ssl, serv_fd);  
    
    if ( SSL_connect(ssl) == FAIL ) 
        ERR_print_errors_fp(stderr);

    else
    {   char *msg = "Client Test Message. Consider Using wireshark to test me ?? ";
 
        printf("Secure Connection Established:  we are using %s encryption\n", SSL_get_cipher(ssl));


        //If any certs from server show them.
        ShowCerts(ssl);



        SSL_write(ssl, msg, strlen(msg)); 
        
        bytes = SSL_read(ssl, buf, sizeof(buf)); 
        
        buf[bytes] = 0;

        printf("We Received: \"%s\"\n", buf);

        SSL_free(ssl);        
    }


    close(serv_fd);    //CLOSE TCP SOCK
    SSL_CTX_free(ctx);   //Free Context
    return 0;
}
