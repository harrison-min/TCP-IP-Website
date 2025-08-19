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
void closeSocket(SOCKET socketToClose);



int main (int argc, char *argv []) {
	SOCKET serverSocket = serverStartup ();
	
	
	
	serverShutdown ();
}

SOCKET serverStartup() {
	if (initializeWinsock () == false) {
		return INVALID_SOCKET;
	}
	
	struct addrinfo * addr = initializeAddrInfo ();
	if (addr == NULL) {
		return INVALID_SOCKET;
	}
	
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
	struct addrinfo hints, *result = NULL;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	int status = getaddrinfo(NULL, "8080", &hints, &result);
	if(status != 0) {
		fprintf(stderr, "getaddrinfo failed: %s\n", gai_strerror(status));
	}
	
	
	return result;
}

SOCKET createSocket(struct addrinfo* addr) {
	SOCKET newSocket = socket (addr->ai_family, addr->ai_socktype, addr->ai_protocol);
	
	if (newSocket == INVALID_SOCKET) {
		fprintf(stderr, "Socket creation failed %d\n", WSAGetLastError());
		return INVALID_SOCKET;
	}
	
	
	
	return newSocket;
}


void serverShutdown () {
	closeSocket();
	WSACleanup();
}

void closeSocket(SOCKET socketToClose) {
	int result = closesocket(socketToClose);
	
	if (result == SOCKET_ERROR) {
		fprintf(stderr, "closeSocket Failed with error %d\n", WSAGetLastError());
	}
}