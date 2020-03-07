#include "muduo/net/TcpClient.h"
#include "muduo/base/Logging.h"
#include "muduo/net/EventLoop.h"
#include "muduo/net/InetAddress.h"

#include <utility>
#include <stdio.h>
#include <vector>

#include <openssl/ssl.h>
#include <openssl/err.h>


#include "SSL_Helper.h"



using namespace std;
using namespace muduo;
using namespace muduo::net;





class SSLClient : noncopyable
{
public:
	SSLClient(EventLoop* loop, const InetAddress& serverAddr, const string& name)
		: loop_(loop)
		, client_(loop, serverAddr, name)
	{
		
		client_.setConnectionCallback(std::bind(&SSLClient::onClientConnection, this, _1));
		client_.setMessageCallback(std::bind(&SSLClient::onMessage, this, _1, _2, _3));
	}
	
	void start()
	{
		client_.connect();
	}
	
	void onClientConnection(const TcpConnectionPtr& conn)
	{
		if (conn->connected())
		{
			conn->setTcpNoDelay(true);
			LOG_WARN << "connected";
			
			ssl_helper = new SSL_Helper(conn);
			ssl_helper->set_type(SSL_TYPE::CLIENT);
			
			ssl_helper->set_connected_callback(std::bind(&SSLClient::onSSLConnected, this));
			ssl_helper->set_receive_callback(std::bind(&SSLClient::handledata, this, _1, _2, _3));
			
			ssl_helper->onConnection(conn);
			
		}
		else
		{
			
			LOG_WARN << "connect closed";
		}
	}

	void onMessage(const TcpConnectionPtr& conn, Buffer* buf, Timestamp timestamp)
	{
		ssl_helper->onMessage(conn, buf, timestamp);
	}
	
	void onSSLConnected()
	{
		LOG_WARN << "connected";
		char szRequest[1024];
		sprintf(szRequest,
			"GET / HTTP/1.1\r\n"
			"Accept: */*\r\n"
			"Accept-Encoding: identity\r\n"
			"Accept-Language: zh-CN,zh;q=0.9,en;q=0.8\r\n"
			"Host: %s\r\n"
			"Connection: Close\r\n" //keep-alive\r\n"
			"\r\n",
			"localhost"
		);
		string reqStr = string(szRequest);
		ssl_helper->SSLSendData((char*)szRequest, reqStr.size());
	}


	
	int handledata(SSL_Helper* ssl_conn, unsigned char* data, size_t datalen)
	{
		printf("datalen:%d\n%s\n",datalen, data);
		return 0;
	}

	void onDisconnect()
	{
		LOG_WARN << "disconnected";
	}

private:
	string m_reqStr;
	void quit()
	{
		loop_->queueInLoop(std::bind(&EventLoop::quit, loop_));
	}


	EventLoop*  loop_;
	SSL_Helper* ssl_helper;
	TcpClient   client_;
};











int main(int argc, char* argv[])
{
	Logger::setLogLevel(Logger::WARN);

	EventLoop loop;
	
	const char* ip = "192.168.1.201"; //"192.168.1.200";

	uint16_t port = 1443;
	InetAddress serverAddr(ip, port);

	SSLClient client(&loop, serverAddr, "sslClient");
	client.start();

	loop.loop();

}

