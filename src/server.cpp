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

enum SocketRole{
    HOST,
    CLIENT
};

class WinsockInitializer {
    public:
        WinsockInitializer () {
            WSADATA wsaData;
        
            int result = WSAStartup(MAKEWORD(2,2), &wsaData);
            
            if (result != 0) {
                throw std::runtime_error("WSAStartup failed with error code: " + std::to_string(result));
            }
            std::cerr<< "Successful winsock initialization!\n";
        }
        ~WinsockInitializer () {
            std::cerr << "Winsock cleaned up\n";
            WSACleanup();
        }

        WinsockInitializer(const WinsockInitializer &) = delete;
        WinsockInitializer& operator=(const WinsockInitializer&) = delete;
};

class OpenSSLInitializer {
    public:
        OpenSSLInitializer() {
            SSL_library_init();
            OpenSSL_add_all_algorithms();
            SSL_load_error_strings();

            std::cerr << "OpenSSL initialized successfully\n";
        }

        ~OpenSSLInitializer() {
            ERR_free_strings();
            EVP_cleanup();
            std::cerr << "OpenSSL cleaned up\n";
        }

        OpenSSLInitializer(const OpenSSLInitializer&) = delete;
        OpenSSLInitializer& operator=(const OpenSSLInitializer&) = delete;
};

class AddrInfoInitializer {
    private:
        addrinfo * result;

    public:
        AddrInfoInitializer (const std::string & ipAddress, const std::string & port, SocketRole socketType)
            :result (nullptr) {

            addrinfo hints {};
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_protocol = IPPROTO_TCP;

            if (socketType == HOST) {    
                hints.ai_flags = AI_PASSIVE;
            }
            int status = getaddrinfo(ipAddress.c_str(), port.c_str(), &hints, &result);
            if(status != 0) {
                throw std::runtime_error("getaddrinfo failed with error code: " + std::to_string(status));
            }
        }

        ~AddrInfoInitializer() {
            freeaddrinfo(result);
        }

        addrinfo * getAddrInfo ()const {
            return result;
        }
};

class TCPSocket {
    protected:
        SOCKET handle;


    public:

        TCPSocket()
            :handle (INVALID_SOCKET) {}

        ~TCPSocket() {
            if (handle != INVALID_SOCKET) {
                closesocket(handle);
            }
        }

        TCPSocket(const TCPSocket&) = delete;
        TCPSocket& operator=(const TCPSocket&) = delete;

        void create (addrinfo* info) {
            if (handle != INVALID_SOCKET) {
                closesocket(handle);
            }

            handle = socket (info->ai_family, info->ai_socktype, info->ai_protocol);
	
            if (handle == INVALID_SOCKET) {
                throw std::runtime_error ("Socket creation failed\nWSAGetLastError: " +std::to_string(WSAGetLastError()));
            }
        }

        SOCKET getHandle() const{
            return handle;
        }
};

class SSLSocket {
    private:
        SSL_CTX * sslContext;
        SSL* sslStructure;
        TCPSocket& tcpSocket;
        SocketRole socketType;


    public:
        SSLSocket(TCPSocket& incomingSocket, SocketRole declaredType) 
            :sslContext(nullptr), sslStructure(nullptr), tcpSocket(incomingSocket), socketType(declaredType) {
                const SSL_METHOD * method;
                if (socketType == CLIENT) {
                    method = TLS_client_method();
                } else if (socketType == HOST) {
                    method = TLS_server_method();
                } else throw std::runtime_error ("SocketType not recognized in SSLSocket");

                sslContext = SSL_CTX_new(method);
                if (sslContext == nullptr) {
                    throw std::runtime_error("Failed to create SSL Context");
                }

                sslStructure = SSL_new(sslContext);
                if (sslStructure == nullptr) {
                    throw std::runtime_error("Failed to create SSL Structure");
                }

                //TO DO: This is obviously a hacky way to get a 64 bit SOCKET to fit in a 32 bit POSIX hole. Unfortunately I am building in a windows 64 bit environment
                SOCKET s = tcpSocket.getHandle();
                if (s > INT_MAX) {
                    throw std::runtime_error("Socket handle too large for OpenSSL");
                }
                SSL_set_fd(sslStructure, static_cast<int>(s));
        }

        ~SSLSocket () {
            if (sslStructure != nullptr) {
                SSL_shutdown(sslStructure);
                SSL_free(sslStructure);
            }
            if (sslContext != nullptr) {
                SSL_CTX_free(sslContext);
            }
        }

        SSLSocket(const SSLSocket&) = delete;
        SSLSocket& operator=(const SSLSocket&) = delete;

        void handshake () {
            int result;
            if (socketType == CLIENT) {
                result = SSL_connect(sslStructure);
            } else {
                result = SSL_accept(sslStructure);
            }

            if (result<=0) {
                throw std::runtime_error("SSL handshake failed with error code: " + std::to_string(SSL_get_error(sslStructure, result)));
            }

            std::cerr<<"SSL handshake successful!\n";
        }
};


class TCPHostSocket {
    private:
        TCPSocket socket;
        addrinfo* info; 

    public:

        TCPHostSocket (const AddrInfoInitializer& newInfo) 
            : info (newInfo.getAddrInfo()){}

        void create () {
            socket.create(info);
        }

        void bind () {
            int bindResult = ::bind(socket.getHandle(), info->ai_addr, (int)info->ai_addrlen);
            if (bindResult !=0) {
                throw std::runtime_error ("Socket binding failed\nWSAGetLastError: " +std::to_string(WSAGetLastError()));
            }
        }

        void listen () {
            int listenResult = ::listen(socket.getHandle(), SOMAXCONN);

            if (listenResult == SOCKET_ERROR) {
                throw std::runtime_error ("Socket listening failed\nWSAGetLastError: " +std::to_string(WSAGetLastError()));
            }
                
            std::cerr<<"Server socket creation success! Socket is now listening...\n";
        }

        void change(AddrInfoInitializer newInfo) {
            info = newInfo.getAddrInfo();
        }

        TCPSocket& getSocket() {
            return socket;
        }
};

class TCPClientSocket {
    private:
        TCPSocket socket;
        addrinfo * info;

    public:

        TCPClientSocket (const AddrInfoInitializer& newInfo)
            :info(newInfo.getAddrInfo()){}

        void create () {
            socket.create(info);
        }

        void connect() {            
            int connectResult = ::connect(socket.getHandle(), info->ai_addr, (int)info->ai_addrlen);
            if (connectResult == SOCKET_ERROR) {
                throw std::runtime_error ("Client connection failed\nWSAGetLastError: " +std::to_string(WSAGetLastError()));
            }
                
            std::cerr<<"Client socket creation success! Socket is now connecting...\n";
        }
        
        void changeInfo (AddrInfoInitializer newInfo) {
            info = newInfo.getAddrInfo();
        }

        TCPSocket& getSocket() {
            return socket;
        }
};

int main () {
    WinsockInitializer winsock;
    OpenSSLInitializer openssl;

    std::string ip = "127.0.0.1";
    std::string port = "32796";

    AddrInfoInitializer hostInfo (ip, port, HOST);
    AddrInfoInitializer clientInfo (ip, port, CLIENT);

    TCPHostSocket myHost (hostInfo);
    TCPClientSocket myClient (clientInfo);

    myHost.create();
    myHost.bind();
    myHost.listen();
    
    myClient.create();
    myClient.connect();

    SSLSocket sslClient (myClient.getSocket(), CLIENT);
    SSLSocket sslHost (myHost.getSocket(), HOST);

    
    sslClient.handshake();
}