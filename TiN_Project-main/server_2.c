// Server
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <time.h>

#define PORT 8080
#define MAXLINE 1024


struct auth_header {
  uint8_t msgType;
  uint32_t challenge;
}__attribute__((packed));


struct CR{
	uint32_t ch;
	uint32_t resp;
} cr_pairs[3];

int main() {
	int sockfd;
	struct sockaddr_in servaddr, cliaddr;
	
	// Creating socket file descriptor
	if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
		perror("socket creation failed");
		exit(EXIT_FAILURE);
	}
	
	memset(&servaddr, 0, sizeof(servaddr));
	memset(&cliaddr, 0, sizeof(cliaddr));
	
	// Filling server information
	servaddr.sin_family = AF_INET; // IPv4
	servaddr.sin_addr.s_addr = inet_addr("172.17.0.2");
	servaddr.sin_port = htons(PORT);
	
	// Bind the socket with the server address
	if ( bind(sockfd, (const struct sockaddr *)&servaddr,sizeof(servaddr)) < 0 )
	{
		perror("bind failed");
		exit(EXIT_FAILURE);
	}
	
	int len, n;

	len = sizeof(cliaddr);


	//filling the challenge response pairs
	cr_pairs[0].ch = 0x000000A1;
	cr_pairs[0].resp = 0x000000A2;
	cr_pairs[1].ch = 0x000000B1; 
	cr_pairs[1].resp = 0x000000B2;
	cr_pairs[2].ch = 0x000000C1; 
	cr_pairs[2].resp = 0x000000C2;
	

	struct auth_header *request_msg = (struct auth_header *)malloc(sizeof(struct auth_header));
	struct auth_header *response_msg = (struct auth_header *)malloc(sizeof(struct auth_header));
	
	//receive request message from client - step1
	n = recvfrom(sockfd, (struct auth_header *)request_msg, MAXLINE,MSG_WAITALL, ( struct sockaddr *) &cliaddr,&len);
        if(n<0)
	{
		printf("\nrequest packet receive failed\n");
		exit(0);
	}
	printf("\nrequest message received form client\n");

	uint8_t value = request_msg->msgType;
	printf("\nrequest message msgType value: %d\n", value);

	if(value == 0){
		printf("\nThis is the request packet\n");
	}	
	
	//generate random number between 0-2 for sending challenge response pairs
	srand(time(0));
	int random_idx = rand() % 3;
	
	//  challenge and ACK messages to be sent from server to client
	struct auth_header *challenge_msg = (struct auth_header *)malloc(sizeof(struct auth_header)) ;
	struct auth_header *ack_msg = (struct auth_header *)malloc(sizeof(struct auth_header));

	challenge_msg->msgType = 0x01;
	challenge_msg->challenge = cr_pairs[random_idx].ch;
	
	// send the challenge message -> STEP 2
	n=sendto(sockfd, challenge_msg, sizeof(struct auth_header),MSG_CONFIRM,(const struct sockaddr *)&cliaddr, len);
	if(n<0){
		printf("\nChallenge Message Sending Failed\n");
		exit(0);
	}
	printf("\nChallenge Message Sent\n");
	printf("\n challenge message value is : %d",challenge_msg->challenge);

	//receive the response msg -> STEP 3
	n=recvfrom(sockfd,response_msg,MAXLINE, MSG_WAITALL, (struct sockaddr *)&cliaddr, &len);
	if(n<0){
		printf("\nResponse Message REceive error\n");
		exit(0);
	}
	printf("\nResponse Message Received\n");
	uint8_t msgType = response_msg->msgType;
	if(msgType != 0x02){
		printf("\nnot a response message\n");
		exit(0);
	}
	printf("\nResponse packet received\n");
	printf("\nresponse value is %d\n", response_msg->challenge);
	if(response_msg->challenge == cr_pairs[random_idx].resp)
	{
		printf("\nAuthentication Successfull\n");
		ack_msg->msgType = 0x03;
		ack_msg->challenge = 0x000000EF;

		sendto(sockfd, ack_msg, sizeof(struct auth_header), MSG_CONFIRM, (const struct sockaddr *)&cliaddr, len);
		printf("\nACK authentication successfull packet sent\n");

	}
	else
	{
		printf("\nAuthentication Failed\n");
		ack_msg->msgType = 0x03;
		ack_msg->challenge = 0x000000FE;	
		sendto(sockfd, ack_msg, sizeof(struct auth_header), MSG_CONFIRM, (const struct sockaddr *)&cliaddr, len);
		printf("\nACK authentication failed packet sent\n");

	}


	// freeing the memory 
	free(request_msg);
	free(response_msg);
	free(challenge_msg);
	free(ack_msg);

	close(sockfd);
	return 0;
}

