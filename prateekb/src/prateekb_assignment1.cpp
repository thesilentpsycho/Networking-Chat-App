/**
 * @prateekb_assignment1
 * @author  Prateek Bhuwania <prateekb@buffalo.edu>
 * @version 1.0
 *
 * @section LICENSE
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details at
 * http://www.gnu.org/copyleft/gpl.html
 *
 * @section DESCRIPTION
 *
 * This contains the main function. Add further description here....
 */
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <strings.h>
#include <map>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "../include/global.h"
#include "../include/logger.h"

using namespace std;

#define BACKLOG 5
#define STDIN 0
#define TRUE 1
#define CMD_SIZE 100
#define MSG_SIZE 256
#define BUFFER_SIZE 256
#define UDP_PORT 53

enum Command
{
    IP,
    AUTHOR,
    PORT,
	LIST
};

struct CommandMap : public std::map<std::string, Command>
{
    CommandMap()
    {
        this->operator[]("IP") =  IP;
        this->operator[]("AUTHOR") = AUTHOR;
        this->operator[]("PORT") = PORT;
		this->operator[]("LIST") = LIST;
    };
    ~CommandMap(){}
};

void log_success(const char* command_str, const char* msg){
	cse4589_print_and_log("[%s:SUCCESS]\n", command_str);
	cse4589_print_and_log(msg);
	cse4589_print_and_log("[%s:END]\n", command_str);
}

void log_error(const char* command_str){
	cse4589_print_and_log("[%s:ERROR]\n", command_str);
	cse4589_print_and_log("[%s:END]\n", command_str);
}

int whats_my_ip(char *str)
{
    struct sockaddr_in udp;
    int temp_udp =socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    int len = sizeof(udp);
    
    if (temp_udp == -1)
    {
        return 0;
    }
    
    memset((char *) &udp, 0, sizeof(udp));
    udp.sin_family = AF_INET;
    udp.sin_port = htons(UDP_PORT);
    inet_pton(AF_INET, "8.8.8.8", &udp.sin_addr);
    
    if (connect(temp_udp, (struct sockaddr *)&udp, sizeof(udp)) < 0)
    {
        return 0;
    }
    if (getsockname(temp_udp,(struct sockaddr *)&udp,(unsigned int*) &len) == -1)
    {
        return 0;
    }
    
    inet_ntop(AF_INET, &(udp.sin_addr), str, len);
    return 1;
}

void act_on_command(char *cmd){
	char buffer [10000];
	string my_command = std::string(cmd);
	if (!my_command.empty() && my_command[my_command.length()-1] == '\n') {
    	my_command.erase(my_command.length()-1);
	}
	CommandMap map = CommandMap();
	Command command;
	if(map.count(my_command)){
		command = map[my_command];
	} else {
		log_error(my_command.c_str());
		return;
	}

	char* ip_addr;
	int ip_success = 0;

	switch (command)
	{
	case AUTHOR:
		sprintf(buffer, "I, %s, have read and understood the course academic integrity policy.\n",
		"prateekb");
		log_success(my_command.c_str(), buffer);
		break;
	case IP:
		char ip_str[INET_ADDRSTRLEN];
		ip_success = whats_my_ip(ip_str);
		if(ip_success == 1) {
			sprintf(buffer, "IP:%s\n", ip_str);
			log_success(my_command.c_str(), buffer);
		} else {
			log_error(my_command.c_str());
		}
		break;
	default:
		break;
	}
}


void start_server(char **argv)
{
	
	int server_socket, head_socket, selret, sock_index, fdaccept=0; 
	unsigned int caddr_len;
	struct sockaddr_in client_addr;
	struct addrinfo hints, *res;
	fd_set master_list, watch_list;

	/* Set up hints structure */
	memset(&hints, 0, sizeof(hints));
    	hints.ai_family = AF_INET;
    	hints.ai_socktype = SOCK_STREAM;
    	hints.ai_flags = AI_PASSIVE;

	/* Fill up address structures */
	if (getaddrinfo(NULL, argv[2], &hints, &res) != 0)
		perror("getaddrinfo failed");
	
	/* Socket */
	server_socket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if(server_socket < 0)
		perror("Cannot create socket");
	
	/* Bind */
	if(bind(server_socket, res->ai_addr, res->ai_addrlen) < 0 )
		perror("Bind failed");

	freeaddrinfo(res);
	
	/* Listen */
	if(listen(server_socket, BACKLOG) < 0)
		perror("Unable to listen on port");
	
	/* ---------------------------------------------------------------------------- */
	
	/* Zero select FD sets */
	FD_ZERO(&master_list);
	FD_ZERO(&watch_list);
	
	/* Register the listening socket */
	FD_SET(server_socket, &master_list);
	/* Register STDIN */
	FD_SET(STDIN, &master_list);
	
	head_socket = server_socket;
	
	while(TRUE){
		memcpy(&watch_list, &master_list, sizeof(master_list));
		
		//printf("\n[PA1-Server@CSE489/589]$ ");
		//fflush(stdout);
		
		/* select() system call. This will BLOCK */
		selret = select(head_socket + 1, &watch_list, NULL, NULL, NULL);
		if(selret < 0)
			perror("select failed.");
		
		/* Check if we have sockets/STDIN to process */
		if(selret > 0){
			/* Loop through socket descriptors to check which ones are ready */
			for(sock_index=0; sock_index<=head_socket; sock_index+=1){
				
				if(FD_ISSET(sock_index, &watch_list)){
					
					/* Check if new command on STDIN */
					if (sock_index == STDIN){
						char *cmd = (char*) malloc(sizeof(char)*CMD_SIZE);
						
						memset(cmd, '\0', CMD_SIZE);
						if(fgets(cmd, CMD_SIZE-1, stdin) == NULL) //Mind the newline character that will be written to cmd
							exit(-1);
						
						act_on_command(cmd);
						printf("\nI got: %s\n", cmd);
						
						//Process PA1 commands here ...
						
						free(cmd);
					}
					/* Check if new client is requesting connection */
					else if(sock_index == server_socket){
						caddr_len = sizeof(client_addr);
						fdaccept = accept(server_socket, (struct sockaddr *)&client_addr, &caddr_len);
						if(fdaccept < 0)
							perror("Accept failed.");
						
						printf("\nRemote Host connected!\n");                        
						
						/* Add to watched socket list */
						FD_SET(fdaccept, &master_list);
						if(fdaccept > head_socket) head_socket = fdaccept;
					}
					/* Read from existing clients */
					else{
						/* Initialize buffer to receieve response */
						char *buffer = (char*) malloc(sizeof(char)*BUFFER_SIZE);
						memset(buffer, '\0', BUFFER_SIZE);
						
						if(recv(sock_index, buffer, BUFFER_SIZE, 0) <= 0){
							close(sock_index);
							printf("Remote Host terminated connection!\n");
							
							/* Remove from watched list */
							FD_CLR(sock_index, &master_list);
						}
						else {
							//Process incoming data from existing clients here ...
							
							printf("\nClient sent me: %s\n", buffer);
							printf("ECHOing it back to the remote host ... ");
							if(send(fdaccept, buffer, strlen(buffer), 0) == strlen(buffer))
								printf("Done!\n");
							fflush(stdout);
						}
						
						free(buffer);
					}
				}
			}
		}
	}
}

int connect_to_host(char *server_ip, char* server_port)
{
	int fdsocket;
	struct addrinfo hints, *res;

	/* Set up hints structure */	
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	/* Fill up address structures */	
	if (getaddrinfo(server_ip, server_port, &hints, &res) != 0)
		perror("getaddrinfo failed");

	/* Socket */
	fdsocket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if(fdsocket < 0)
		perror("Failed to create socket");
	
	/* Connect */
	if(connect(fdsocket, res->ai_addr, res->ai_addrlen) < 0)
		perror("Connect failed");
	
	freeaddrinfo(res);

	return fdsocket;
}


int start_client(char **argv)
{	
	struct sockaddr_in client;
	socklen_t clientsz = sizeof(client);

	int server;
	char* server_ip;
	char* server_port;

	server = connect_to_host(server_ip, server_port);

	//getting client-side socket details
	getsockname(server, (struct sockaddr *) &client, &clientsz);
	uint client_port = ntohs(client.sin_port);
	std::cout<< "Port-->"<<client_port<<std::endl;
	char buffer[20];
	sprintf(buffer, "%u", client_port);
	log_success("PORT", buffer);

	while(TRUE){
		printf("\n[PA1-Client@CSE489/589]$ ");
		fflush(stdout);
		
		char *msg = (char*) malloc(sizeof(char)*MSG_SIZE);
		memset(msg, '\0', MSG_SIZE);
		if(fgets(msg, MSG_SIZE-1, stdin) == NULL) //Mind the newline character that will be written to msg
			exit(-1);
		
		// printf("I got: %s(size:%d chars)", msg, strlen(msg));
		
		printf("\nSENDing it to the remote server ... ");
		if(send(server, msg, strlen(msg), 0) == strlen(msg))
			printf("Done!\n");
		fflush(stdout);
		
		/* Initialize buffer to receieve response */
		char *buffer = (char*) malloc(sizeof(char)*BUFFER_SIZE);
		memset(buffer, '\0', BUFFER_SIZE);
		
		if(recv(server, buffer, BUFFER_SIZE, 0) >= 0){
			printf("Server responded: %s", buffer);
			fflush(stdout);
		}
	}
}

/**
 * main function
 *
 * @param  argc Number of arguments
 * @param  argv The argument list
 * @return 0 EXIT_SUCCESS
 */
int main(int argc, char **argv)
{
	/*Init. Logger*/
	cse4589_init_log(argv[2]);

	/* Clear LOGFILE*/
    fclose(fopen(LOGFILE, "w"));

	/*Start Here*/
	if(argc != 3){
		printf("Usage:%s [type:s/c] [port]\n", argv[0]);
		exit(-1);
	}

	if (std::string(argv[1]) == "s") {
		start_server(argv);
	} else if (std::string(argv[1]) == "c") {

	} else {
		printf("Usage:%s [type:s/c] [port]\n", argv[0]);
		exit(-1);
	}
	return 0;
}
