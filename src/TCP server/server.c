#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <winsock2.h>


SOCKET serverStartup();
bool initializeWinsock ();
struct addrinfo * initializeAddrInfo ();
SOCKET createSocket(struct addrinfo* addr);

void serverShutdown();
void closeSocket();



int main (int argc, char *argv []) {
	SOCKET serverSocket = serverStartup ();
	
	
	
	serverShutdown ();
}

SOCKET serverStartup() {
	if (initializeWinsock ()) {
		return INVALID_SOCKET;
	}
	
	struct addrinfo * addr = initializeAddrInfo ();
	SOCKET serverSocket = createSocket(addr);
	
	freeaddrinfo(addr);
	
	return serverSocket;
}

bool initializeWinsock () {
	WSADATA wsaData;
	
	int result = WSAStartup(MAKEWORD(2,2), &wsaData);
	
	if (result != 0) {
		fprintf(stderr,"WSAStartup failed: %d\n", result);
		return false;
	}
	
	return true;
}


struct addrinfo * initializeAddrInfo () {
	struct addrinfo hints, *result;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	getaddrinfo(NULL, "8080", &hints, &result);
	
	return result;
}

SOCKET createSocket(struct addrinfo* addr) {
	
}


void serverShutdown () {
	WSACleanup();
	closeSocket();
}