#include "muduo/base/Logging.h"
#include "muduo/net/EventLoop.h"
#include "muduo/net/InetAddress.h"
#include "muduo/net/TcpServer.h"
#include "cert.h"


#include <utility>
#include <stdio.h>
#include <vector>
#include <functional>
#include <memory>

#include "SSL_Helper.h"








using namespace muduo;
using namespace muduo::net;
using namespace std;


class SSLServer : noncopyable
{
private:
	map<TcpConnectionPtr, SSL_HelperPtr> m_connMap;
	TcpServer server_;


public:
	SSLServer(EventLoop* loop,
		const InetAddress& serverAddr,
		const string& name
	): server_(loop, serverAddr, name)
	{
		server_.setConnectionCallback(std::bind(&SSLServer::onServerConnection, this, _1));
		server_.setMessageCallback(std::bind(&SSLServer::onMessage, this, _1, _2, _3));
	}


	void start()
	{
		server_.start();
	}
	
	void stop()
	{
		loop_->queueInLoop(std::bind(&EventLoop::quit, loop_));
	}
	
	void onSSL_connected()
	{
		if (m_SSL_connected_callback)
			m_SSL_connected_callback();

	}


	void set_connected_callback(function<void()> fun) { m_SSL_connected_callback = fun; }
	void set_receive_callback(function<int(unsigned char*, size_t)> fun) { m_SSL_receive_callback = fun; }

private:
	function<void()> m_SSL_connected_callback;
	function<int(unsigned char*, size_t)> m_SSL_receive_callback;
	function<void()> m_SSL_closed_callback;


	
	void onServerConnection(const TcpConnectionPtr& conn)
	{
		if (conn->connected())
		{
			conn->setTcpNoDelay(true);
			LOG_WARN << "connected";
			SSL_HelperPtr ssl_helper = make_shared<SSL_Helper>(conn);
			ssl_helper->set_type(SSL_TYPE::SERVER);
			m_connMap[conn] = ssl_helper;
			ssl_helper->set_receive_callback(std::bind(&SSLServer::handledata, this, _1, _2, _3));
			ssl_helper->onConnection(conn);
			//std::bind(&SSL_Helper::onMessage, this, _1, _2, _3)
			//conn->setConnectionCallback()
		}
		else
		{
			m_connMap.erase(conn);
			LOG_WARN << "connect closed";
		}
	}

	void onMessage(const TcpConnectionPtr& conn, Buffer* buf, Timestamp timestamp)
	{
		auto&  ssl_helper = m_connMap[conn];
		ssl_helper->onMessage(conn, buf, timestamp);
	}


	
	void close_session()
	{
		printf("close_session()\n");
	}

public:

	int handledata( SSL_Helper* ssl_conn, unsigned char* data, size_t datalen)
	{
		printf("handdledata, datalen:%d\n%s\n", datalen, data);

		char szRequest[1024];
		string html = "<h1>this message is from ssl server</h1>";
		sprintf(szRequest,
			"HTTP/1.1 200 OK\r\n"
			"Content-Length: %d\r\n"
			"Connection: keep-alive\r\n"
			"\r\n"
			"%s",
			html.length(),
			html.c_str()
		);
		string reqStr = string(szRequest);
		ssl_conn->SSLSendData((char*)szRequest, reqStr.size());
		return 0;
	}

	void quit()
	{
		loop_->queueInLoop(std::bind(&EventLoop::quit, loop_));
	}


	EventLoop* loop_;
};




int main(int argc, char* argv[])
{
	Logger::setLogLevel(Logger::WARN);
	EventLoop loop;

	const char* ip = "0.0.0.0"; //"192.168.1.200";

	int16_t port = 1443;
	InetAddress listenAddr(ip, port);
	

	SSLServer server(&loop, listenAddr, "https server");
	server.start();

	loop.loop();
}

