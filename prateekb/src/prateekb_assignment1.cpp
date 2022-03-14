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
	LOGOUT,
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
	string from;
	string to;
	string msg;
};

// Taking some globals I disapprove usually.
std::vector<Message> pending_messages;
std::vector<Client> client_list;
std::vector<Block> block_list;
//local copy of blocked ips
std::vector<string> c_block_list;
//local copy of client
std::vector<Client> c_client_list;
const char* LOGGEDIN = "logged-in";
const char* LOGGEDOUT = "logged-out";

struct CommandMap : public std::map<std::string, Command>
{
    CommandMap()
    {
        this->operator[]("IP") =  IP;
        this->operator[]("AUTHOR") = AUTHOR;
        this->operator[]("PORT") = PORT;
		this->operator[]("LIST") = LIST;
		this->operator[]("LOGIN") = LOGIN;
		this->operator[]("LOGOUT") = LOGOUT;
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

void log_success_simple(string cmnd){
	cse4589_print_and_log("[%s:SUCCESS]\n", cmnd.c_str());
	cse4589_print_and_log("[%s:END]\n", cmnd.c_str());
}

void log_error(const char* command_str){
	cse4589_print_and_log("[%s:ERROR]\n", command_str);
	cse4589_print_and_log("[%s:END]\n", command_str);
}

void log_relay_message(string from, string msg){
	cse4589_print_and_log("[%s:SUCCESS]\n", "RECEIVED");
	cse4589_print_and_log("msg from:%s\n[msg]:%s\n", from.c_str(), msg.c_str());
	cse4589_print_and_log("[%s:END]\n", "RECEIVED");
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
			break;
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

Client* find_client_by_fd(int fd){
	for (auto& c : client_list){
		if (c.client_fd == fd)
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

string concat(vector<string> vec, string delimiter){
	if(vec.size() == 0) return "";
	if(vec.size() == 1) return vec[0];
	ostringstream concatenated;
	copy(vec.begin(), vec.end(),
           ostream_iterator<std::string>(concatenated, delimiter.c_str()));
	string result = concatenated.str();
	if (!result.empty()) {
    	result.resize(result.length() - delimiter.length()); // trim trailing delimiter. such a shame
	}

	return result;
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
		}
		
		//receive logged-in client details
		char temp[512];
		if(recv(client_fd, &temp, sizeof temp, 0) > 0){
			string dat(temp);
			// cout<< dat<< endl;
			c_client_list.clear();
			if(dat != ""){
				vector<string> clients = split(dat, "::::");
				if(clients.size() >= 1){
					// detail includes data in this format ip::hostname
					vector<string> details = split(clients[0], "$$");
					for(auto& d:details){
						vector<string> curr_detail = split(d, "::");
						Client c = {
							curr_detail[0], 
							-1, 
							curr_detail[1],
							std::stoi(curr_detail[2]),
							1,
							0,
							0
						};
						c_client_list.push_back(c);
					}
				}
			}
		}

		//pull pending messages one by one
		uint32_t un;
		if(recv(client_fd, &un, sizeof(uint32_t), 0) > 0){
			int total = ntohl(un);
			for (int i = 1; i <= total; i++)
			{
				char temp[512];
				if(recv(client_fd, &temp, sizeof temp, 0) > 0){
					string dat(temp);
					vector<string> mess = split(dat, "$$");
					log_relay_message(mess[0], mess[1]);
				}
			}
		}
		cse4589_print_and_log("[%s:SUCCESS]\n", my_command.c_str());
		cse4589_print_and_log("[%s:END]\n", my_command.c_str());

		break;
	case LIST:
		logged_in_clients = is_client ? c_client_list: get_logged_in_clients();
		std::sort(logged_in_clients.begin(), logged_in_clients.end());
		cse4589_print_and_log("[%s:SUCCESS]\n", my_command.c_str());
		for (int index = 0; index < logged_in_clients.size(); ++index){
			cse4589_print_and_log("%-5d%-35s%-20s%-8d\n", 
			index + 1, logged_in_clients[index].hostname.c_str(),
			logged_in_clients[index].ip.c_str(), logged_in_clients[index].port_no);
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
	string client_hostname;
	if(hostname && hostname->h_name){
		client_hostname = hostname->h_name;
	} else{
		client_hostname = "testpc";
	}

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

vector<Message> filter_pending_messages(string to_ip){
	vector<Message> result;
	for(auto& m:pending_messages){
		if(m.to == to_ip){
			result.push_back(m);
		}
	}

	return result;
}

bool is_online(string ip){
	for(auto& c: client_list){
		if(c.ip == ip && c.login_status == 1){
			return true;
		}
	}
	return false;
}

int find_client_fd_from_ip(string ip){
	for(auto& c: client_list){
		if(c.ip == ip){
			return c.client_fd;
		}
	}
	return 0;
}

int send_data_over_socket(int socket_id, string data){
	char *msg = (char*) malloc(sizeof(char)*MSG_SIZE);
	memset(msg, '\0', MSG_SIZE);
	strcpy(msg, data.c_str());
	int bytes_sent = send(socket_id, msg, strlen(msg), 0);
	free(msg);

	return bytes_sent > 0 ? bytes_sent : -1;
}

bool is_blocked(string blocker, string blocked){
	for(auto& entry: block_list){
		if(entry.blocked == blocked && entry.blocker == blocker){
			return true;
		}
	}
	return false;
}

void relay_message_from_server(string to_ip, string message_body, int from_fd){
	Client* sender = find_client_by_fd(from_fd);

	if(is_blocked(to_ip, sender->ip)){
		//ignore message. pathetic!
		return;
	}

	Client* temp1 = find_client(to_ip);
	temp1->count_received += 1;

	if(!is_online(to_ip)){
		pending_messages.push_back({sender->ip, to_ip, message_body});
		return;
	}
	//sending right now
	int receiver_handle = find_client_fd_from_ip(to_ip);
	string data = sender->ip + "::::" + message_body;

	send_data_over_socket(receiver_handle, data);	
}

void unblock_user(string to_be_unblocked, int from_fd){
	Client* sender = find_client_by_fd(from_fd);

	if(is_blocked(sender->ip, to_be_unblocked)){
		for(auto it = block_list.begin(); it != block_list.end();){
			if(it->blocked == to_be_unblocked && it->blocker == sender->ip){
				it = block_list.erase(it); 
			} else {
				++it;
			}
		}
	}
}

void block_user(string to_be_blocked, int from_fd){
	Client* sender = find_client_by_fd(from_fd);

	if(!is_blocked(sender->ip, to_be_blocked)){
		block_list.push_back({sender->ip, to_be_blocked});
	}
}

void broadcast_message_from_server(string message_body, int from_fd){
	Client* sender = find_client_by_fd(from_fd);

	for(auto& c: client_list){
		if(c.ip != sender->ip){
			relay_message_from_server(c.ip, message_body, from_fd);
		}
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

						//server shell command received
						string ss_cmd(cmd);
						vector<string> ss_command = split(ss_cmd, " ");
						
						if(ss_command[0] == "BLOCKED"){
							if(ss_command.size() != 2){
								log_error(ss_command[0].c_str());
								free(cmd);
								continue;
							}
							if(!is_valid_ip(ss_command[1])){
								log_error(ss_command[0].c_str());
								free(cmd);
								continue;
							}
							bool found = false;
							for(auto& c:client_list){
								if(c.ip == ss_command[1]){
									found = true;
								}
							}
							if(!found){
								log_error(ss_command[0].c_str());
								free(cmd);
								continue;
							}
							cse4589_print_and_log("[%s:SUCCESS]\n", ss_command[0].c_str());
							vector<Client> temp_list;
							for(auto& b:block_list){
								if(b.blocker == ss_command[1])
									temp_list.push_back(*find_client(b.blocked));
							}
							std::sort(temp_list.begin(), temp_list.end());
							int idx = 0;
							for(auto& xyz: temp_list){
								idx += 1;
								cse4589_print_and_log("%-5d%-35s%-20s%-8d\n", 
								idx, xyz.hostname.c_str(), xyz.ip.c_str(), xyz.port_no);
							}
							cse4589_print_and_log("[%s:END]\n", ss_command[0].c_str());
						} else if(ss_command[0] == "STATISTICS"){
							std::sort(client_list.begin(), client_list.end());
							cse4589_print_and_log("[%s:SUCCESS]\n", ss_command[0].c_str());
							int idx1 = 0;
							string lin = "logged-in";
							string lout = "logged-out";
							for(auto& c: client_list){
								idx1 += 1;
								cse4589_print_and_log("%-5d%-35s%-8d%-8d%-8s\n",
								idx1, c.hostname.c_str(), c.count_sent, c.count_received,
								c.login_status == 1 ? lin.c_str() : lout.c_str());
							}
							cse4589_print_and_log("[%s:END]\n", ss_command[0].c_str());
						} else{
							act_on_command(cmd, port, false, -1);
						}
						
						free(cmd);
					}
					/* Check if new client is requesting connection */
					else if(sock_index == server_socket){
						caddr_len = sizeof(client_addr);
						fdaccept = accept(server_socket, (struct sockaddr *)&client_addr, &caddr_len);
						if(fdaccept < 0)
							perror("Accept failed.");
						
						//or update status
						add_new_client(fdaccept, client_addr);

						//send logged-in client details
						vector<Client> clients = get_logged_in_clients();
						vector<string> clientIPs;
						for (auto& c : clients){
							clientIPs.push_back(c.ip + "::" + c.hostname + "::" + to_string(c.port_no));
						}
						string data = concat(clientIPs, "$$");
						char *msg = (char*) malloc(sizeof(char)*MSG_SIZE);
						memset(msg, '\0', MSG_SIZE);
						strcpy(msg, data.c_str());
						send(fdaccept, msg, strlen(msg), 0);

						//send number of pending messages for this client
						memset(msg, '\0', MSG_SIZE);
						char ip[INET_ADDRSTRLEN];
						inet_ntop(AF_INET, &(client_addr.sin_addr), ip, INET_ADDRSTRLEN);
						string client_ip(ip);
						vector<Message> messages = filter_pending_messages(client_ip);
						uint32_t un = htonl(messages.size());
						if(send(fdaccept, &un, sizeof(uint32_t), 0) == sizeof(uint32_t)){
							// send pending messages one by one
							for(auto& m: messages){
								string encoded_data = m.from + "$$" + m.msg;
								memset(msg, '\0', MSG_SIZE);
								strcpy(msg, encoded_data.c_str());
								send(fdaccept, msg, strlen(msg), 0);
							}
						}

						free(msg);
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
							/* Remove from watched list */
							FD_CLR(sock_index, &master_list);
							//set as logged out
							for (auto it = begin (client_list); it != end (client_list); ++it) {
								if(it->client_fd == sock_index){
									it->login_status = 0;
								}
							}
							printf("Remote Host terminated connection!\n");
						}
						else {
							//Process incoming data from existing clients here ...
							
							string c_msg = "";
							if(buffer){
								c_msg = buffer;
							}
							string s_cmd(c_msg);
							cout << "Client sent me: " << s_cmd << endl;
							vector<string> s_command = split(s_cmd, "::::");
							if(s_command[0] == "REFRESH") {
								//send neighbours
								vector<Client> clients = get_logged_in_clients();
								vector<string> clientIPs;
								for (auto& c : clients){
									clientIPs.push_back(c.ip + "::" + c.hostname + "::" + to_string(c.port_no));
								}
								string data = concat(clientIPs, "$$");
								char *msg = (char*) malloc(sizeof(char)*MSG_SIZE);
								memset(msg, '\0', MSG_SIZE);
								strcpy(msg, data.c_str());
								send(sock_index, msg, strlen(msg), 0);
								free(msg);
							} else if (s_command[0] == "SEND"){
								vector<string> details = split(s_command[1], "$$");
								Client* temp1 = find_client_by_fd(sock_index);
								temp1->count_sent += 1;
								relay_message_from_server(details[0] , details[1], sock_index);
								string tempc = "RELAYED";
								cse4589_print_and_log("[%s:SUCCESS]\n", tempc.c_str());
								cse4589_print_and_log("msg from:%s, to:%s\n[msg]:%s\n"
										, temp1->ip.c_str(), details[0].c_str(), details[1].c_str());
								cse4589_print_and_log("[%s:END]\n", tempc.c_str());
							} else if(s_command[0] == "BROADCAST"){
								Client* temp1 = find_client_by_fd(sock_index);
								temp1->count_sent += 1;
								broadcast_message_from_server(s_command[1], sock_index);

								string tempc = "RELAYED";
								string dummy = "255.255.255.255";
								cse4589_print_and_log("[%s:SUCCESS]\n", tempc.c_str());
								cse4589_print_and_log("msg from:%s, to:%s\n[msg]:%s\n"
										, temp1->ip.c_str(), dummy.c_str(), s_command[1].c_str());
								cse4589_print_and_log("[%s:END]\n", tempc.c_str());
							} else if(s_command[0] == "BLOCK"){
								block_user(s_command[1], sock_index);
							} else if(s_command[0] == "UNBLOCK"){
								unblock_user(s_command[1], sock_index);
							}
							fflush(stdout);
						}
						
						free(buffer);
					}
				}
			}
		}
	}

	close(server_socket);
}

int get_new_binding(int port){
	int client_fd = 0;

	client_fd = socket(AF_INET, SOCK_STREAM, 0);
	if(client_fd == 0){
		exit(EXIT_FAILURE);
	}

	int option = 1;
	setsockopt(client_fd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

	struct sockaddr_in client_addr;
	client_addr.sin_addr.s_addr = INADDR_ANY;
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = htons(port);

	if(bind(client_fd, (struct sockaddr *)&client_addr,sizeof(struct sockaddr_in)) < 0){
		perror("socket");
		exit(EXIT_FAILURE);		//fatal
	}

	return client_fd;
}

void receive_neighbours(int client_fd){
	//receive logged-in client details
	char *msg = (char*) malloc(sizeof(char)*MSG_SIZE);
	memset(msg, '\0', MSG_SIZE);

	if(recv(client_fd, msg, MSG_SIZE, 0) > 0){
		string dat = msg;
		// cse4589_print_and_log("\nDAT:%s", dat.c_str());
		c_client_list.clear();
		if(dat != ""){
			vector<string> clients = split(dat, "::::");
			if(clients.size() >= 1){
				// detail includes data in this format ip::hostname
				vector<string> details = split(clients[0], "$$");
				for(auto& d:details){
					vector<string> curr_detail = split(d, "::");
					Client c = {
						curr_detail[0], 
						-1, 
						curr_detail[1],
						std::stoi(curr_detail[2]),
						1,
						0,
						0
					};
					c_client_list.push_back(c);
				}
			}
		}
	}

	free(msg);
}

int start_client(int port)
{	
	int client_fd = 10;

	struct sockaddr_in server_addr;
	
	int select_result, sock_index;

	fd_set master_list, watch_list;
	FD_ZERO(&master_list);
	FD_ZERO(&watch_list);
	FD_SET(STDIN, &master_list);

	char *msg = (char*) malloc(sizeof(char)*MSG_SIZE);

	while(TRUE) {
		memcpy(&watch_list, &master_list, sizeof(master_list));

		select_result = select(client_fd + 1, &watch_list, NULL, NULL, NULL);

		if(select_result > 0){
			if(FD_ISSET(STDIN, &watch_list)) {
				/* we have new msg on STDIN to process */
					char *cmd = (char*) malloc(sizeof(char)*CMD_SIZE);
					
					memset(cmd, '\0', CMD_SIZE);
					if(fgets(cmd, CMD_SIZE-1, stdin) == NULL)
						exit(-1);
					
					cmd[strcspn(cmd, "\n")] = '\0';
					
					string c_cmd(cmd);
					vector<string> c_command = split(c_cmd, " ");
					if(c_command[0] == "LOGOUT"){
						close(client_fd);
						FD_CLR(client_fd, &master_list);
						// // client_fd = get_new_binding(port);
						cse4589_print_and_log("[%s:SUCCESS]\n", c_command[0].c_str());
						cse4589_print_and_log("[%s:END]\n", c_command[0].c_str());
						free(cmd);
						continue;
					} else if (c_command[0] == "LOGIN"){
						cout << "direct login" << endl;
						if(c_command.size() != 3){
							log_error(c_command[0].c_str());
							free(cmd);
							continue;
						} else if(!is_valid_ip(c_command[1]) || !is_number(c_command[2].c_str())){
							log_error(c_command[0].c_str());
							free(cmd);
							continue;
						}
						int server_port = atoi(c_command[2].c_str());
						if(server_port < 1 || server_port > 65535){
							log_error(c_command[0].c_str());
							free(cmd);
							continue;
						}

						server_addr.sin_family = AF_INET;
						server_addr.sin_addr.s_addr = inet_addr(c_command[1].c_str());
						server_addr.sin_port = htons(server_port);
						client_fd = get_new_binding(port);
						if(connect(client_fd, (struct sockaddr*) &server_addr, sizeof server_addr) != 0){
							perror("socket cant connect");
							free(cmd);
							continue;
						}
						
						receive_neighbours(client_fd);

						//pull pending messages one by one
						uint32_t un;
						if(recv(client_fd, &un, sizeof(uint32_t), 0) > 0){
							int total = ntohl(un);
							for (int i = 1; i <= total; i++)
							{
								char temp[512];
								if(recv(client_fd, &temp, sizeof temp, 0) > 0){
									string dat(temp);
									vector<string> mess = split(dat, "$$");
									log_relay_message(mess[0], mess[1]);
								}
							}
						}

						FD_SET(client_fd, &master_list);
						cse4589_print_and_log("[%s:SUCCESS]\n", c_command[0].c_str());
						cse4589_print_and_log("[%s:END]\n", c_command[0].c_str());
					} else if (c_command[0] == "REFRESH") {
						//TODO: Ask for the list from the server here
						memset(msg, '\0', MSG_SIZE);
						strcpy(msg, c_command[0].c_str());

						if(send(client_fd, msg, strlen(msg), 0) == strlen(msg)){
							receive_neighbours(client_fd);
							cse4589_print_and_log("[%s:SUCCESS]\n", c_command[0].c_str());
							cse4589_print_and_log("[%s:END]\n", c_command[0].c_str());
						} else{
							log_error(c_command[0].c_str());
						}
					} else if(c_command[0] == "SEND"){
						
						if(c_command.size() >= 3 && is_valid_ip(c_command[1])){
							int index = c_cmd.find(" ");
							c_cmd = c_cmd.substr(index+1);
							index = c_cmd.find(" ");
							string message_body = c_cmd.substr(index+1);
							string to_ip = c_cmd.substr(0,index);

							string encoded_data = "SEND::::" + to_ip + "$$" + message_body;
							memset(msg, '\0', MSG_SIZE);
							strcpy(msg, encoded_data.c_str());

							if(send(client_fd, msg, strlen(msg), 0) == strlen(msg)) {
								log_success_simple(c_command[0]);
							}
						} else {
							log_error(c_command[0].c_str());
						}
					} else if (c_command[0] == "BROADCAST"){
						if(c_command.size() >= 2) {
							int index = c_cmd.find(" ");
							string message_body = c_cmd.substr(index+1);
							string encoded_data = "BROADCAST::::" + message_body;
							if (send_data_over_socket(client_fd, encoded_data) > 0)
								log_success_simple(c_command[0]);
						} else{
							log_error(c_command[0].c_str());
						}
					} else if(c_command[0] == "BLOCK"){
						//cout << "### a" << endl;
						if(c_command.size() == 2){
							//cout << "### b" << endl;
							string to_be_blocked_ip = c_command[1];
							if(!is_valid_ip(to_be_blocked_ip)){
								//cout << "### c" << endl;
								log_error(c_command[0].c_str());
								free(cmd);
								continue;
							}
							bool is_already_blocked = false;
							for(auto& blocked_ip: c_block_list){
								//cout << "### d" << endl;
								if(blocked_ip == to_be_blocked_ip){
									is_already_blocked = true;
									break;
								}
							}
							if(is_already_blocked){
								log_error(c_command[0].c_str());
								free(cmd);
								continue;
							}

							//cout << "### e" << endl;
							bool found = false;
							for(auto& c: c_client_list){
								if(c.ip == to_be_blocked_ip){
									//cout << "### f" << endl;
									found = true;
								}
							}
							//should not block ip which we don't know about
							if(!found){
								//cout << "### g" << endl;
								log_error(c_command[0].c_str());
								free(cmd);
								continue;
							}
							//cout << "### h" << endl;
							string encoded_data = "BLOCK::::" + to_be_blocked_ip;
							if(send_data_over_socket(client_fd, encoded_data) > 0){
								//cout << "### i" << endl;
								c_block_list.push_back(to_be_blocked_ip);	//blocked locally
								log_success_simple(c_command[0]);
							}
						} else{
							//cout << "### j" << endl;
							log_error(c_command[0].c_str());
						}
					} else if(c_command[0] == "UNBLOCK"){
						//cout << "### a" << endl;
						if(c_command.size() == 2){
							//cout << "### b" << endl;
							string to_be_unblocked_ip = c_command[1];
							if(!is_valid_ip(to_be_unblocked_ip)){
								//cout << "### c" << endl;
								log_error(c_command[0].c_str());
								free(cmd);
								continue;
							}
							bool is_already_blocked = false;
							for(auto& blocked_ip: c_block_list){
								//cout << "### d" << endl;
								if(blocked_ip == to_be_unblocked_ip){
									is_already_blocked = true;
									break;
								}
							}
							if(!is_already_blocked){
								log_error(c_command[0].c_str());
								free(cmd);
								continue;
							}

							//cout << "### e" << endl;
							bool found = false;
							for(auto& c: c_client_list){
								if(c.ip == to_be_unblocked_ip){
									//cout << "### f" << endl;
									found = true;
								}
							}
							//should not block ip which we don't know about
							if(!found){
								//cout << "### g" << endl;
								log_error(c_command[0].c_str());
								free(cmd);
								continue;
							}
							//cout << "### h" << endl;
							string encoded_data = "UNBLOCK::::" + to_be_unblocked_ip;
							if(send_data_over_socket(client_fd, encoded_data) > 0){
								//cout << "### i" << endl;
								c_block_list.erase(
									std::remove(c_block_list.begin(), c_block_list.end(), to_be_unblocked_ip), c_block_list.end());
								log_success_simple(c_command[0]);
							}
						} else{
							//cout << "### j" << endl;
							log_error(c_command[0].c_str());
						}
					} else {
						act_on_command(cmd, port, true, client_fd);
					}

					free(cmd);
			} else if(FD_ISSET(client_fd, &watch_list)) {
				memset(msg, '\0', MSG_SIZE);

				int val = recv(client_fd, msg, MSG_SIZE, 0);
				string data(msg);
				if(val > 0) {
					vector<string> parts = split(data, "::::");
					cse4589_print_and_log("[RECEIVED:SUCCESS]\n");
					cse4589_print_and_log("msg from:%s\n[msg]:%s\n", parts[0].c_str() , parts[1].c_str());
					cse4589_print_and_log("[RECEIVED:END]\n");
				}
			}
		}
	}
	
	close(client_fd);
	free(msg);
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
