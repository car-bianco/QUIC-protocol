#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>



#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>

#ifndef min
#define min(a,b)            (((a) < (b)) ? (a) : (b))
#endif

//Receive File Function

int recvFile(int sockfd, struct sockaddr * client_addr){

   // variable for file operation
   char buffer[BUFSIZ];
   int file_size;
   FILE *received_file;
   int remain_data = 0;
   ssize_t len;
   int read_return;
   int fd;


//	struct sockaddr_in client_addr;
//	bzero(&serv_addr,sizeof(serv_addr));
//	int length= sizeof(client_addr);

	recv(sockfd, buffer, BUFSIZ, 0);

	printf("File size: %s\n", buffer);
        file_size = atoi(buffer);

  fd = open("New2.pdf",
                O_WRONLY | O_CREAT | O_TRUNC,
                S_IRUSR | S_IWUSR);

	printf("opening file for writing: New2.pdf\n");
	//received_file = fopen("New.pdf", "w");   //open that new file in write mode
        if (fd == -1)
        {
                perror("Failed to create file-> ");

                exit(1);
        }

	printf("file opened for writing\n");

        remain_data = file_size;
	printf("Remaining data = %d\n", remain_data); 


        do {
            read_return = read(sockfd, buffer, BUFSIZ);
            //if (read_return < BUFSIZ)
	    //	break;
	    if (read_return == -1) {
                perror("read");
                exit(EXIT_FAILURE);
            }
            if (write(fd, buffer, read_return) == -1) {
                perror("write");
                exit(EXIT_FAILURE);
            }
	    remain_data -= read_return;
	    printf("Remaining data = %d\n", remain_data); 
        } while (remain_data > 0);

	printf("Recv of file done \n");
        close(fd);
	return file_size;
        
}

int main(){
	int socketDscrp= socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(socketDscrp<0){
		printf("XXXXXXXX   UDP Socket creation failed	XXXXXXXX\n");	
		exit(1);
	}
	else{
		printf("******	UDP Socket created with Descriptor: %d\n", socketDscrp);
	}
	printf("\nSocket in operation\n\n");

	struct sockaddr_in serv_addr, client_addr;
//	bzero(&serv_addr,sizeof(serv_addr));
	int sendbuff, rcvbuff;
	socklen_t optlen = sizeof(sendbuff);
	//getsockopt(socketDscrp, SOL_SOCKET, SO_SNDBUF, &sendbuff, &optlen);
	//getsockopt(socketDscrp, SOL_SOCKET, SO_RCVBUF, &rcvbuff, &optlen);

	//printf("Socket sendbuff size = %d bytes, rcvbuff size = %d bytes\n", sendbuff, rcvbuff);

	serv_addr.sin_family= AF_INET;
	serv_addr.sin_port= htons(4420);
	//serv_addr.sin_addr.s_addr= inet_addr("127.0.0.1");
	serv_addr.sin_addr.s_addr= inet_addr("192.168.1.148");

	client_addr.sin_family= AF_INET;
	client_addr.sin_port= htons(4421);
	//client_addr.sin_addr.s_addr= inet_addr("127.0.0.1");
	client_addr.sin_addr.s_addr= inet_addr("192.168.1.8");

	int binding= bind(socketDscrp, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
	if(binding<0){
		printf("XXXXXXXX	binding failed	XXXXXXXX\n");
		exit(3);
	}
	else{
		printf("******	Binding successful\n");
	}
	char * msg;
	msg = "ack";
	int len= sizeof(serv_addr);

/*	int receive= recvfrom(socketDscrp, msg, 1000, 0, (struct sockaddr *) &client_addr, &len);
	printf("received= %d\n",receive);
	if(receive<0){
		printf("Data recieve failed\n");
		exit(4);
	}
	else{
		printf("Received data is: %s\n", msg);
	}
*/
	printf("Waiting to receive file..........\n");

	recvFile(socketDscrp, (struct sockaddr *)&client_addr);
   	sendto(socketDscrp,msg,sizeof(msg),0,(struct sockaddr *)&client_addr,sizeof(client_addr));
	printf("File receive finished\n");

	int closing= close(socketDscrp);
	if(closing<0){
		printf("XXXXXXX	Socket closure failed, Aborting	XXXXXXXXXX");
		exit(2);
	}
	else{
		printf("*******	Socket closed successfully\n");
	}

	return(0);

}

	


