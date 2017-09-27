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

int recvFile(int sockfd){

   // variable for file operation
   char buffer[BUFSIZ];
   int file_size;
   FILE *received_file;
   int remain_data = 0;
   ssize_t len;
   int read_return;
   int fd;


	struct sockaddr_in client_addr;
//	bzero(&serv_addr,sizeof(serv_addr));
	int length= sizeof(client_addr);

	recv(sockfd, buffer, BUFSIZ, 0);

	printf("File size: %s\n", buffer);
        file_size = atoi(buffer);

  fd = open("New3.pdf",
                O_WRONLY | O_CREAT | O_TRUNC,
                S_IRUSR | S_IWUSR);

	printf("opening file for writing: New3.pdf\n");
	//received_file = fopen("New.pdf", "w");   //open that new file in write mode
        if (fd == -1)
        {
                perror("Failed to create file-> ");

                exit(1);
        }

	printf("file opened for writing\n");

        remain_data = file_size;
	printf("STREAM 2: Remaining data = %d\n", remain_data); 


        do {
            read_return = read(sockfd, buffer, BUFSIZ);
            if (read_return == 0)
		break;
	    if (read_return == -1) {
                perror("read");
                exit(EXIT_FAILURE);
            }
            if (write(fd, buffer, read_return) == -1) {
                perror("write");
                exit(EXIT_FAILURE);
            }
	    remain_data -= read_return;
	    printf("STREAM 2: Remaining data = %d\n", remain_data); 
        } while (remain_data > 0);

	printf("Recv of file done \n");
        close(fd);
	return file_size;
        
}

int main(){
	int socketDscrp= socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(socketDscrp<0){
		printf("XXXXXXXX	TCP Socket creation failed	XXXXXXXX\n");
		exit(1);
	}
	else{
		printf("******	TCP Socket created with Descriptor: %d\n", socketDscrp);
	}
	printf("\nSocket in operation\n\n");
	setsockopt(socketDscrp,SOL_SOCKET,SO_REUSEADDR,&(int){1},sizeof(int));
	struct sockaddr_in serv_addr, client_addr;
//	bzero(&serv_addr,sizeof(serv_addr));

	serv_addr.sin_family= PF_INET;
	serv_addr.sin_port= htons(5420);
//	serv_addr.sin_addr.s_addr= inet_addr("127.0.0.1");
	serv_addr.sin_addr.s_addr= inet_addr("192.168.1.148");

	client_addr.sin_family= PF_INET;
	client_addr.sin_port= htons(5421);
//	client_addr.sin_addr.s_addr= inet_addr("127.0.0.1");
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
    socklen_t peer_size = sizeof(struct sockaddr_in);
    if(listen(socketDscrp,32)==0)
        printf("Listening\n");
    else
        printf("Error\n");
    int newSocket = accept(socketDscrp, (struct sockaddr *) &client_addr, &peer_size);
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

	recvFile(newSocket);
    //write(socketDscrp,msg,sizeof(msg));
	printf("File receive finished\n");

	int closing= close(socketDscrp);
	if(closing<0){
		printf("XXXXXXX	Socket closure failed, Aborting	XXXXXXXXXX");
		exit(2);
	}
	else{
		printf("*******	STREAM 2: Socket closed successfully\n");
	}

	return(0);

}

	


