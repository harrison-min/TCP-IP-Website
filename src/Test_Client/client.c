#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>


#include <winsock2.h>
#include <ws2tcpip.h>

SOCKET clientStartup();
bool initializeWinsock ();
struct addrinfo * initializeAddrInfo ();
SOCKET createSocket(struct addrinfo* addr);

void clientTest (SOCKET clientSocket);
void twoWayCommunication (SOCKET clientSocket);

void clientShutdown(SOCKET socketToClose);
void closeSocket(SOCKET socketToClose);



int main (int argc, char *argv []) {
	SOCKET clientSocket = clientStartup ();
	
	clientTest(clientSocket);
	
	
	clientShutdown (clientSocket);
}

SOCKET clientStartup() {
	if (initializeWinsock () == false) {
		return INVALID_SOCKET;
	}
	
	struct addrinfo * addr = initializeAddrInfo ();
	if (addr == NULL) {
		return INVALID_SOCKET;
	}
	
	SOCKET clientSocket = createSocket(addr);
	
	freeaddrinfo(addr);
	
	return clientSocket;
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
	hints.ai_flags = 0;
	
	char * IPAddress = "10.169.4.205";
	char * port = "5000";

	int status = getaddrinfo(IPAddress, port, &hints, &result);
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
	
	int connectResult = connect(newSocket, addr->ai_addr, (int)addr->ai_addrlen);
	if (connectResult == SOCKET_ERROR) {
        fprintf(stderr, "Connection to server failed: %d\n", WSAGetLastError());
        closesocket(newSocket);
        return INVALID_SOCKET;
    }
	
	fprintf(stderr,"Socket connection success! Connection is now open...\n");
	
	
	return newSocket;
}

void clientTest(SOCKET clientSocket) {
	
	const char *openingMessage = "Hello from client!\n";
	send(clientSocket, openingMessage, strlen(openingMessage), 0);
	
	twoWayCommunication(clientSocket);
	
	fprintf(stderr,"Press enter to close the client... \n");
	getchar();
	
}

void twoWayCommunication (SOCKET clientSocket) {
	
	int bufferSize = 512;
	char buffer[bufferSize];

	while (true) {
		int bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
		if (bytesReceived <= 0) {
			break; // Connection closed or error
		}

		buffer[bytesReceived] = '\0';
		printf("Server says: %s", buffer);

		fprintf(stderr, "From Client: ");

		char responseBuffer [bufferSize];
		fgets (responseBuffer, bufferSize-1, stdin);
		
		
		send(clientSocket, responseBuffer, strlen(responseBuffer), 0);
	}
}

void clientShutdown (SOCKET socketToClose) {
	if (socketToClose!= INVALID_SOCKET) {
		closeSocket(socketToClose);
	}
	WSACleanup();
}

void closeSocket(SOCKET socketToClose) {
	int result = closesocket(socketToClose);
	
	if (result == SOCKET_ERROR) {
		fprintf(stderr, "closeSocket Failed with error %d\n", WSAGetLastError());
	}
}