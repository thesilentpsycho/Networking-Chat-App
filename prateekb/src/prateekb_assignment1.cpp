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
#include <algorithm>
#include <vector>
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
#include <sstream>
#include <iterator>

#include "../include/global.h"
#include "../include/logger.h"

using namespace std;

#define BACKLOG 5
#define STDIN 0
#define TRUE 1
#define CMD_SIZE 100
#define MSG_SIZE 512
#define BUFFER_SIZE 512
#define UDP_PORT 53

enum Command
{
    IP,
    AUTHOR,
    PORT,
	LIST,
	LOGIN,
	SEND,
	BROADCAST,
	BLOCK,
	UNBLOCK,
	STATISTICS
};

enum NodeType {
	CLIENT,
	SERVER
};

struct Client {
    string ip;
    int client_fd;
    string hostname;
	int port_no;
    int login_status;	//1 = in	0 = out
    int count_received;
    int count_sent;

	// to sort based on port. often used.
	bool operator<(const Client& a) const
    {
        return port_no < a.port_no;
    }
};

struct Block{
	string blocker;
	string blocked;
};

struct Message {
	int id;
	string from;
	string to;
	string msg;
};

// Taking some globals I disapprove usually.
std::vector<Message> pending_messages;
std::vector<Client> client_list;
std::vector<Block> block_list;

struct CommandMap : public std::map<std::string, Command>
{
    CommandMap()
    {
        this->operator[]("IP") =  IP;
        this->operator[]("AUTHOR") = AUTHOR;
        this->operator[]("PORT") = PORT;
		this->operator[]("LIST") = LIST;
		this->operator[]("LOGIN") = LOGIN;
		this->operator[]("SEND") = SEND;
		this->operator[]("BROADCAST") = BROADCAST;
		this->operator[]("BLOCK") = BLOCK;
		this->operator[]("UNBLOCK") = UNBLOCK;
		this->operator[]("STATISTICS") = STATISTICS;

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

//https://stackoverflow.com/questions/5607589/right-way-to-split-an-stdstring-into-a-vectorstring
vector<string> split(string str, string token){
    vector<string>result;
    while(str.size()){
        int index = str.find(token);
        if(index!=string::npos){
            result.push_back(str.substr(0,index));
            str = str.substr(index+token.size());
            if(str.size()==0)result.push_back(str);
        }else{
            result.push_back(str);
            str = "";
        }
    }
    return result;
}

bool is_valid_ip(const string &ip)
{
    struct sockaddr_in temp;
    int result = inet_pton(AF_INET, ip.c_str(), &(temp.sin_addr));
    return result != 0;
}

bool is_number(const std::string& str)
{
    std::string::const_iterator it = str.begin();
    while (it != str.end() && std::isdigit(*it)) ++it;
    return !str.empty() && it == str.end();
}

vector<Client> get_logged_in_clients(){
	std::vector<Client> result;
	for (auto& c : client_list){
		if (c.login_status == 1)
			result.push_back(c);
	}
	return result;
}

Client* find_client(string& client_ip){
	for (auto& c : client_list){
		if (c.ip == client_ip)
			return &c;
	}
	return nullptr;
}

bool is_logged_in(string client_ip){
	Client* client = find_client(client_ip);
	if(client){
		if(client->login_status == 1){
			return true;
		}
	}

	return false;
}

void act_on_command(char *cmd, int port, bool is_client, int client_fd){
	char buffer [10000];
	char *msg = (char*) malloc(sizeof(char)*MSG_SIZE);

	vector<string> command_chunks = split(std::string(cmd), " ");
	string my_command = command_chunks[0];

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
	struct sockaddr_in server_addr;
	int server_port;
	ostringstream concatenated;
	string encoded_data;
	vector<Client> logged_in_clients;

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
			return;
		}
		break;
	case PORT:
		sprintf(buffer, "PORT:%d\n", port);
		log_success(my_command.c_str(), buffer);
		break;
	case LOGIN:
		if(command_chunks.size() != 3){
			log_error(my_command.c_str());
			return;
		} else if(!is_valid_ip(command_chunks[1]) || !is_number(command_chunks[2].c_str())){
			log_error(my_command.c_str());
			return;
		}

		server_port = atoi(command_chunks[2].c_str());
		if(server_port < 1 || server_port > 65535){
			log_error(my_command.c_str());
			return;
		}

		server_addr.sin_family = AF_INET;
    	server_addr.sin_addr.s_addr = inet_addr(command_chunks[1].c_str());
    	server_addr.sin_port = htons(server_port);
		if(connect(client_fd, (struct sockaddr*) &server_addr, sizeof server_addr) != 0){
			log_error(my_command.c_str());
			return;
		} else{
			log_success(my_command.c_str(), buffer);
		}
		break;
	case SEND:
		if(command_chunks.size() < 3){
			log_error(my_command.c_str());
			return;
		} else if(!is_valid_ip(command_chunks[1])){
			log_error(my_command.c_str());
			return;
		}
		copy(command_chunks.begin() + 2, command_chunks.end(),
           ostream_iterator<std::string>(concatenated, " "));

		encoded_data = "SEND_ONE::::" + command_chunks[1] + "::::" + concatenated.str();
		memset(msg, '\0', MSG_SIZE);
		strcpy(msg, encoded_data.c_str());

		if(send(client_fd, msg, strlen(msg), 0) == strlen(msg))
			log_success(my_command.c_str(), buffer);
		break;
	case BROADCAST:
		if(command_chunks.size() < 2){
			log_error(my_command.c_str());
			return;
		}
		copy(command_chunks.begin() + 1, command_chunks.end(),
           ostream_iterator<std::string>(concatenated, " "));

		encoded_data = "SEND_ALL::::" + concatenated.str();
		memset(msg, '\0', MSG_SIZE);
		strcpy(msg, encoded_data.c_str());

		if(send(client_fd, msg, strlen(msg), 0) == strlen(msg))
			log_success(my_command.c_str(), buffer);
		break;
	case BLOCK:
		if(command_chunks.size() < 2){
			log_error(my_command.c_str());
			return;
		}
		copy(command_chunks.begin() + 1, command_chunks.end(),
           ostream_iterator<std::string>(concatenated, " "));

		encoded_data = "BLOCK::::" + concatenated.str();
		memset(msg, '\0', MSG_SIZE);
		strcpy(msg, encoded_data.c_str());

		if(send(client_fd, msg, strlen(msg), 0) == strlen(msg))
			log_success(my_command.c_str(), buffer);
		break;
	case UNBLOCK:
		if(command_chunks.size() < 2){
			log_error(my_command.c_str());
			return;
		}
		copy(command_chunks.begin() + 1, command_chunks.end(),
           ostream_iterator<std::string>(concatenated, " "));

		encoded_data = "UNBLOCK::::" + concatenated.str();
		memset(msg, '\0', MSG_SIZE);
		strcpy(msg, encoded_data.c_str());

		if(send(client_fd, msg, strlen(msg), 0) == strlen(msg))
			log_success(my_command.c_str(), buffer);
		break;
	case LIST:
		logged_in_clients = get_logged_in_clients();
		std::sort(logged_in_clients.begin(), logged_in_clients.end());
		cse4589_print_and_log("[%s:SUCCESS]\n", my_command.c_str());
		for (int index = 0; index < logged_in_clients.size(); ++index){
			cse4589_print_and_log("%-5d%-35s%-20s%-8d\n", 
			index + 1, logged_in_clients[index].hostname,
			logged_in_clients[index].ip, logged_in_clients[index].port_no);	
		}
		cse4589_print_and_log("[%s:END]\n", my_command.c_str());
		break;
	case STATISTICS:
		std::sort(client_list.begin(), client_list.end());
		cse4589_print_and_log("[%s:SUCCESS]\n", my_command.c_str());
		for (int index = 0; index < client_list.size(); ++index) {
			cse4589_print_and_log("%-5d%-35s%-8d%-8d%-8s\n",
			index + 1, client_list[index].hostname,
			client_list[index].count_sent, client_list[index].count_received,
			client_list[index].login_status == 1 ? "logged-in": "logged-out");	
		}
		cse4589_print_and_log("[%s:END]\n", my_command.c_str());
		break;
	default:
		break;
	}

	free(msg);
}

void add_new_client(int client_fd, struct sockaddr_in client_addr){
	char ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(client_addr.sin_addr), ip, INET_ADDRSTRLEN);
	string client_ip(ip);

	bool found = false;
	for (auto it = begin (client_list); it != end (client_list); ++it) {
    	if(it->ip == client_ip){
			found = true;
			it->port_no = ntohs(client_addr.sin_port);
			it->client_fd = client_fd;
			it->login_status = 1;
		}
	}

	struct hostent *hostname = NULL;
	hostname = gethostbyaddr(&(client_addr.sin_addr), sizeof(client_addr.sin_addr), AF_INET);
	string client_hostname(hostname->h_name);

	if(!found){
		Client c = {
			client_ip, 
			client_fd, 
			client_hostname,
			ntohs(client_addr.sin_port),
			1,
			0,
			0
		};
		client_list.push_back(c);
	}
}


void start_server(int port)
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
	if (getaddrinfo(NULL, std::to_string(port).c_str(), &hints, &res) != 0)
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
						
						cmd[strcspn(cmd, "\n")] = '\0';
						act_on_command(cmd, port, false, -1);
						
						free(cmd);
					}
					/* Check if new client is requesting connection */
					else if(sock_index == server_socket){
						caddr_len = sizeof(client_addr);
						fdaccept = accept(server_socket, (struct sockaddr *)&client_addr, &caddr_len);
						if(fdaccept < 0)
							perror("Accept failed.");
						
						add_new_client(fdaccept, client_addr);
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


int start_client(int port)
{	
	int client_fd = 0;

	client_fd = socket(AF_INET, SOCK_STREAM, 0);
	if(client_fd == 0){
		exit(EXIT_FAILURE);
	}

	struct sockaddr_in client_addr, server_addr;
	client_addr.sin_addr.s_addr = INADDR_ANY;
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = htons(port);

	if(bind(client_fd, (struct sockaddr *)&client_addr,sizeof(struct sockaddr_in)) < 0){
		exit(EXIT_FAILURE);		//fatal
	}

	fd_set master_list, watch_list;
	int cmax = 0, select_result, sock_index;

	FD_ZERO(&master_list);
	FD_ZERO(&watch_list);
	FD_SET(client_fd, &master_list);
	FD_SET(STDIN, &master_list);
	
	int head_socket = client_fd;
	char receive_buf[1024];

	while(TRUE) {
		memcpy(&watch_list, &master_list, sizeof(master_list));
		
		select_result = select(head_socket + 1, &watch_list, NULL, NULL, NULL);
		if(select_result < 0)
			perror("select failed.");
		
		/* Check if we have server message/STDIN to process */
		if(select_result > 0){
			/* Loop through socket descriptors to check which ones are ready */
			for(sock_index=0; sock_index<=head_socket; sock_index+=1){
				
				if(FD_ISSET(sock_index, &watch_list)){
					
					/* Check if new command on STDIN */
					if (sock_index == STDIN){
						char *cmd = (char*) malloc(sizeof(char)*CMD_SIZE);
						
						memset(cmd, '\0', CMD_SIZE);
						if(fgets(cmd, CMD_SIZE-1, stdin) == NULL) //Mind the newline character that will be written to cmd
							exit(-1);
						
						cmd[strcspn(cmd, "\n")] = '\0';
						act_on_command(cmd, port, true, client_fd);
						printf("\nI got: %s\n", cmd);
						
						//Process PA1 commands here ...
						
						free(cmd);
					}
					/* Check if server has sent something */
					else if(sock_index == client_fd) {
						memset(receive_buf, 0, sizeof receive_buf);

						if(recv(client_fd, &receive_buf, sizeof receive_buf, 0) > 0) {
							vector<string> parts = split(receive_buf, "::::");
							string command = parts[0];
							if(command == "MSG") {
								char temp_buf[sizeof receive_buf];
								string disp_command = "RECEIVED";
								sprintf(temp_buf, "msg from:%s\n[msg]:%s\n",
								parts[1].c_str(), parts[2].c_str());
								log_success(disp_command.c_str(), temp_buf);
							}
						}
					}
					/* Read from existing clients */
					else{
						/* Initialize buffer to receieve response */
						
					}
				}
			}
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

	int port = atoi(argv[2]);
	if (std::string(argv[1]) == "s") {
		start_server(port);
	} else if (std::string(argv[1]) == "c") {
		start_client(port);
	} else {
		printf("Usage:%s [type:s/c] [port]\n", argv[0]);
		exit(-1);
	}
	return 0;
}
