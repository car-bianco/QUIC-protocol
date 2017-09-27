#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>

#ifndef min
#define min(a,b)            (((a) < (b)) ? (a) : (b))
#endif

// Send File Function
int sendFile(int sockfd, struct sockaddr * serv_addr){
	int len, rc, status = 0;
	// file operation variables
	int fd;
	int sent_bytes = 0;
	char file_size[32];
	struct stat file_stat;
	off_t * offset;
	int remain_data;
	int read_return;
	char buffer[BUFSIZ];

	fd = open("File.pdf", O_RDONLY);
        
 	if (fd == -1)
        {
	      perror("Error opening file: ");
              exit(EXIT_FAILURE);
         }

         /* Get file stats */
         if (fstat(fd, &file_stat) < 0)
         {
              perror("Error fstat --> ");

              exit(EXIT_FAILURE);
         }

        fprintf(stdout, "File Size: \n%zd bytes\n", file_stat.st_size);

	sprintf(file_size,"%zd",file_stat.st_size);
        
        /* Sending file size */
        //rc = send(sockfd, file_size, sizeof(file_size), 0);
        rc = sendto(sockfd, file_size, sizeof(file_size), 0, serv_addr, sizeof(*serv_addr));
        if (rc < 0 && errno > 0)
        {
            perror("Error while sending file size > ");

            exit(1);
        }

        fprintf(stdout, "Sent the file size\n");

        offset = 0;
        remain_data = file_stat.st_size;

	printf("Remaining data = %d\n", remain_data);

 while (1) {
        read_return = read(fd, buffer, BUFSIZ);
        if (read_return == 0)
            break;
	remain_data -= read_return;
	printf("Remaining data = %d\n", remain_data);
        if (read_return == -1) {
            perror("read");
            exit(EXIT_FAILURE);
        }
        if (write(sockfd, buffer, read_return) == -1) {
            perror("write");
            exit(EXIT_FAILURE);
        }
}
        
	if(remain_data){
		status = 0;
		printf("Error: data remaining!\n");
	}
	else{
		status = 1;
		printf("No data remaining.\n");
	}
	return status;
}

int main(){
	int socketDscrp= socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(socketDscrp<0){
		printf("XXXXXXXX	Socket creation failed	XXXXXXXX\n");
		exit(1);
	}
	else{
		printf("******	Socket created with Descriptor: %d\n", socketDscrp);
	}
	printf("\nSocket in operation\n\n");
	setsockopt(socketDscrp,SOL_SOCKET,SO_REUSEADDR,&(int){1},sizeof(int));
	struct sockaddr_in serv_addr, client_addr;
//	bzero(&serv_addr,sizeof(serv_addr));

	serv_addr.sin_family= PF_INET;
	serv_addr.sin_port= htons(4420);
//	serv_addr.sin_addr.s_addr= inet_addr("127.0.0.1");
	serv_addr.sin_addr.s_addr= inet_addr("192.168.1.148");

	client_addr.sin_family= PF_INET;
	client_addr.sin_port= htons(4421);
//	client_addr.sin_addr.s_addr= inet_addr("127.0.0.1");
	client_addr.sin_addr.s_addr= inet_addr("192.168.1.20");

	int binding= bind(socketDscrp, (struct sockaddr *) &client_addr, sizeof(client_addr));
	if(binding<0){
		printf("XXXXXXXX	binding failed	XXXXXXXX\n");
		exit(3);
	}
	else{
		printf("******	Binding successful\n");
	}

	int conn= connect(socketDscrp, (struct sockaddr *) &serv_addr, sizeof(client_addr));


	char msg[1000];
/*	printf("Enter message to be sent: ");
//	scanf("%s", msg);
	fgets(msg, 1000, stdin);

	sendto(socketDscrp, msg, 1000, 0, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
*/
	printf("************** Sending File.pdf\n");
	//fgets(msg, 1000, stdin);
	sendFile(socketDscrp, (struct sockaddr *)&serv_addr);

    //while (read(socketDscrp,msg,sizeof(msg))==0);
    //printf("Server has received the file!\n");
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

	


