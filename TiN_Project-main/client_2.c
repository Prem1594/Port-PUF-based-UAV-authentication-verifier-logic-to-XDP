// Client/UAV
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

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
	struct sockaddr_in servaddr;

	// Creating socket file descriptor
	if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
		perror("socket creation failed");
		exit(EXIT_FAILURE);
	}

	memset(&servaddr, 0, sizeof(servaddr));
	
	// Filling server information
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(PORT);
	servaddr.sin_addr.s_addr = inet_addr("172.17.0.2");
	int n, len;
		
	//filling the challenge response pairs
	cr_pairs[0].ch = 0x000000A1;
	cr_pairs[0].resp = 0x000000A2;
	cr_pairs[1].ch = 0x000000B1; 
	cr_pairs[1].resp = 0x000000B2;
	cr_pairs[2].ch = 0x000000C1; 
	cr_pairs[2].resp = 0x000000C2;
	
	// request and response headers
	struct auth_header *auth_request = (struct auth_header*)malloc(sizeof(struct auth_header)); 
	struct auth_header *auth_response = (struct auth_header*)malloc(sizeof(struct auth_header));

	//setting the request message fields
        auth_request->msgType = 0x00;
        auth_request->challenge = 0x0000; //32 bits


	// send the request message -> STEP 1
        sendto(sockfd,(struct auth_header * )auth_request, sizeof(struct auth_header),MSG_CONFIRM,(const struct sockaddr *) &servaddr,
                        sizeof(servaddr) );
        printf("\nClient request message sent\n");

	// challenge and ack packets
	struct auth_header *ch_packet = (struct auth_header *) malloc(sizeof(struct auth_header));
	struct auth_header *ack_packet = (struct auth_header *)malloc(sizeof(struct auth_header));


	// receiving challenge packet from server -> STEP 2
	n = recvfrom(sockfd,ch_packet, MAXLINE, MSG_WAITALL, (struct sockaddr*)&servaddr,&len);
	if(n<0){
		printf("\nchallenge packet receiving error\n");
		exit(0);
	}
	printf("\nChallenge message is received value is %d \n",ch_packet->challenge);

	uint8_t msgType = ch_packet->msgType;
	uint32_t challenge = ch_packet->challenge;


	//get the response corresponding to the challenge 
	int pair_found = 0;
	int i;
	uint32_t response_to_send;
	for (i=0; i<3; i++)
	{
		if(cr_pairs[i].ch==challenge)
		{	
			response_to_send = cr_pairs[i].resp;
			pair_found = 1;
		}
		if(pair_found==1)
			break;
	}


	//respose packet sending
	auth_response->msgType = 0x02;
	auth_response->challenge = response_to_send; //here challenge acts as response since it is response packet
	
	printf("\nresponse send from client is %d ",auth_response->challenge);

	// send the response packet -> STEP 3
	sendto(sockfd,(struct auth_header*)auth_response,sizeof(struct auth_header),
			MSG_CONFIRM,(const struct sockaddr*) &servaddr, sizeof(servaddr));

	printf("\nResponse Message sent\n");

	// receive the ACK packet from the server -> STEP 4
	n=recvfrom(sockfd, ack_packet, MAXLINE, MSG_WAITALL, (struct sockaddr*)&servaddr,&len); 
	if(n<0)
	{
		printf("\nACK packet receive Error\n");
		exit(0);
	}

	printf("\nACK packet received\n");
	if(ack_packet->challenge == 0x000000EF){
		printf("\nAuthentication Successfull\n");
	}
	else{
		printf("\nAuthentication Failed\n");
	}

	//freeing the memory
	
	free(auth_request);
	free(auth_response);
	free(ch_packet);
	free(ack_packet);


	close(sockfd);
	return 0;
}

