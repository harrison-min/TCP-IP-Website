#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>

// Windows Sockets
#include <winsock2.h>
#include <ws2tcpip.h>

//openssl
#include <openssl/ssl.h>
#include <openssl/err.h>

class TCPSocket {
    protected:
        SOCKET handle;

    public:
        TCPSocket()
            :handle (INVALID_SOCKET) {}

        virtual ~TCPSocket() {
            if (handle != INVALID_SOCKET) {
                closesocket(handle);
            }
        }
        SOCKET get() const{
            return handle;
        }
};

class TCPServerSocket : public TCPSocket {
    public:
        void set(addrinfo * info) {
            if (handle != INVALID_SOCKET) {
                closesocket(handle);
            }

            handle = socket (info->ai_family, info->ai_socktype, info->ai_protocol);
	
            if (handle == INVALID_SOCKET) {
                throw std::runtime_error ("Socket creation failed\n" + std::to_string(WSAGetLastError()));
            }
            
            int bindResult = bind(handle, info->ai_addr, (int)info->ai_addrlen);
            if (bindResult !=0) {
                throw std::runtime_error ("Socket binding failed\n" + std::to_string(WSAGetLastError()));
            }

            int listenResult = listen(handle, SOMAXCONN);
            if (listenResult == SOCKET_ERROR) {
                throw std::runtime_error ("Socket listening failed\n" + std::to_string(WSAGetLastError()));
            }
                
            std::cerr<<"Server socket creation success! Socket is now listening...\n";
        }
};

class TCPClientSocket : public TCPSocket {
    public:
        void set(addrinfo * info) {
            if (handle != INVALID_SOCKET) {
                closesocket(handle);
            }

            handle = socket (info->ai_family, info->ai_socktype, info->ai_protocol);
	
            if (handle == INVALID_SOCKET) {
                throw std::runtime_error ("Socket creation failed\n" + std::to_string(WSAGetLastError()));
            }
            
            int connectResult = connect(handle, info->ai_addr, (int)info->ai_addrlen);
            if (connectResult == SOCKET_ERROR) {
                throw std::runtime_error ("Client connection failed\n" + std::to_string(WSAGetLastError()));
            }
                
            std::cerr<<"Client socket creation success! Socket is now connecting...\n";
        }
};

class AddrInfoInitializer {
    private:
        addrinfo * result;

    public:
        AddrInfoInitializer (const std::string & ipAddress, const std::string & port)
            :result (nullptr) {

            addrinfo hints {};
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_protocol = IPPROTO_TCP;
            hints.ai_flags = AI_PASSIVE;

            int status = getaddrinfo(ipAddress.c_str(), port.c_str(), &hints, &result);
            if(status != 0) {
                throw std::runtime_error("getaddrinfo failed with error code: " + std::to_string(status));
            }
        }

        ~AddrInfoInitializer() {
            freeaddrinfo(result);
        }

        addrinfo * get ()const {
            return result;
        }
};

class TCPServer {
    private:
        std::string ipAddress;
        std::string port;
        TCPServerSocket serverSocket;

    public:
        TCPServer(const std::string& IP, const std::string& portNumber)
            : ipAddress(IP), port(portNumber) {

            AddrInfoInitializer info (ipAddress, port);
            serverSocket.set(info.get());

        }
        ~TCPServer() {
            //shutdown server
        }

};

class winsockInitializer {
    public:
        winsockInitializer () {
            WSADATA wsaData;
        
            int result = WSAStartup(MAKEWORD(2,2), &wsaData);
            
            if (result != 0) {
                throw std::runtime_error("WSAStartup failed with error code: " + std::to_string(result));
            }
            std::cerr<< "Successful winsock initialization!\n";
        }
        ~winsockInitializer () {
            WSACleanup();
        }

};


int main () {
    winsockInitializer winsock;

    std::string ip = "127.0.0.1";
    std::string port = "32796";

    TCPServer myServer(ip, port);

}

