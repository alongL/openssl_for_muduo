#include "muduo/net/TcpClient.h"
#include "muduo/base/Logging.h"
#include "muduo/net/EventLoop.h"
#include "muduo/net/InetAddress.h"

#include <utility>

#include <stdio.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <vector>
using namespace std;


enum OVERLAPPED_TYPE
{
	RECV = 0,
	SEND = 1
};



using namespace muduo;
using namespace muduo::net;



class SSLSession : noncopyable
{
public:

	SSLSession(EventLoop* loop,
		const InetAddress& serverAddr,
		const string& name
		)
		: client_(loop, serverAddr, name)
	{
		m_EncryptedSendData.resize(1024 * 10);
		m_DecryptedRecvData.resize(1024 * 10);
		m_CurrRecived = 0;
		m_BytesSizeRecieved = 0;
		m_TotalRecived = 0;
		m_Handshaked = false;


		client_.setConnectionCallback(std::bind(&SSLSession::onConnection, this, _1));
		client_.setMessageCallback(std::bind(&SSLSession::onMessage, this, _1, _2, _3));
				
	}


	void start()
	{
		client_.connect();
	}

	void stop()
	{
		client_.disconnect();
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
	
	
	void onConnection(const TcpConnectionPtr& conn)
	{
		if (conn->connected())
		{
			m_conn = conn;
			conn->setTcpNoDelay(true);
			LOG_WARN << "connected";
			ssl_connect();
		}
		else
		{
			LOG_WARN << "connect closed";
			
		}


	}

	
	void onMessage(const TcpConnectionPtr& conn, Buffer* buf, Timestamp)
	{
		printf("receive data, size:%d \n", buf->readableBytes());
		
		auto datalen = buf->readableBytes();
		m_BytesSizeRecieved += datalen;
		SSLProcessingRecv( buf->peek(), datalen);
		buf->retrieveAll();
	}

	void close_session()
	{
		printf("close_session()\n");
		
	}

public:

	void SSLSendData(char* data, size_t size)
	{
		int	ret = SSL_write(m_Ssl, data, size);
		int	ssl_error = SSL_get_error(m_Ssl, ret);

		if (IsSSLError(ssl_error))
			close_session();

		SSLProcessingSend();
	}

	int ssl_connect()
	{
		init_SSLContext();
		SSL_set_connect_state(m_Ssl);
		SSLProcessingConnect();
		return 1;
	}

	void SSLProcessingConnect()
	{
		int ret;
		int ssl_error;

		int bytesSizeRecieved = 0;
		do
		{
			ret = SSL_read(m_Ssl, m_DecryptedRecvData.data(), m_DecryptedRecvData.size());
			ssl_error = SSL_get_error(m_Ssl, ret);

			if (IsSSLError(ssl_error))
				close_session();

			if (ret > 0)
				bytesSizeRecieved += ret;

		} while (ret > 0);


		if (SSL_is_init_finished(m_Ssl))
		{
			m_Handshaked = true;
			SSLReceiveData();//receive data from ssl sockets
		}


		SSLProcessingSend();
	}

	void SSLReceiveData()
	{

		if (m_SSL_receive_callback)
			m_SSL_receive_callback(m_DecryptedRecvData.data(), m_DecryptedRecvData.size());


		//myprintf("receiveCallback()\n");
		//printf("size:%d \ncontent:%s\n", m_DecryptedRecvData.size(), m_DecryptedRecvData.data());
	
	}


	void SSLProcessingSend( )
	{
		int ret;
		int ssl_error;

		while (BIO_pending(m_Bio[SEND]))
		{
			ret = BIO_read(m_Bio[SEND], m_EncryptedSendData.data(), m_EncryptedSendData.size());

			if (ret > 0)
			{
				m_conn->send(reinterpret_cast<char*>(m_EncryptedSendData.data()), ret);
			}
			else
			{
				ssl_error = SSL_get_error(m_Ssl, ret);

				if (IsSSLError(ssl_error))
					close_session();
			}
		}
	}

	void SSLProcessingRecv(const char*  RecvBuffer, size_t BytesSizeRecieved)
	{
		int ret;
		int ssl_error;

		if (m_BytesSizeRecieved > 0)
		{
			ret = BIO_write(m_Bio[RECV], RecvBuffer, BytesSizeRecieved);

			if (ret > 0)
			{
				int intRet = ret;
				if (intRet > m_BytesSizeRecieved)
					close_session();

				m_BytesSizeRecieved -= intRet;
			}
			else
			{
				ssl_error = SSL_get_error(m_Ssl, ret);
				if (IsSSLError(ssl_error))
					close_session();
			}
		}


		do
		{
			assert(m_DecryptedRecvData.size() - m_CurrRecived > 0);
			ret = SSL_read(m_Ssl, m_DecryptedRecvData.data() + m_CurrRecived, m_DecryptedRecvData.size() - m_CurrRecived);

			if (ret > 0)
			{
				m_CurrRecived += ret;
				m_TotalRecived += ret;

				if (m_Handshaked)
				{
					SSLReceiveData();// m_IOCPBaseParent->OnRecived(this);
				}
			}
			else
			{
				ssl_error = SSL_get_error(m_Ssl, ret);

				if (IsSSLError(ssl_error))
					close_session();// throw EXCEPTION(SSLException(m_Ssl, ret));
			}
		} while (ret > 0);

		if (!m_Handshaked)
		{
			if (SSL_is_init_finished(m_Ssl))
			{
				m_Handshaked = true;
				onSSL_connected();// receiveCallback();// m_IOCPBaseParent->OnTransportConnected(this);
			}
		}


		SSLProcessingSend();
	}

	void init_SSLContext()
	{
		SSL_library_init();
		SSL_load_error_strings();         /* Bring in and register error messages */
										  //OpenSSL_add_all_algorithms();     /* Load cryptos, et.al. */

		m_SslCtx = SSL_CTX_new(SSLv23_method());
		SSL_CTX_set_verify(m_SslCtx, SSL_VERIFY_NONE, nullptr);

		m_Ssl = SSL_new(m_SslCtx);

		m_Bio[SEND] = BIO_new(BIO_s_mem());
		m_Bio[RECV] = BIO_new(BIO_s_mem());
		SSL_set_bio(m_Ssl, m_Bio[RECV], m_Bio[SEND]);
	}

	bool IsSSLError(int ssl_error)
	{
		switch (ssl_error)
		{
		case SSL_ERROR_NONE:
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
		case SSL_ERROR_WANT_CONNECT:
		case SSL_ERROR_WANT_ACCEPT:
			return false;

		default: return true;
		}

	}

private:
	TcpClient client_;
	TcpConnectionPtr m_conn;
	
	
	SSL_CTX *m_SslCtx;
	SSL *m_Ssl; // SSL structure used by OpenSSL
	BIO *m_Bio[2]; // memory BIO used by OpenSSL

	bool m_Handshaked;

	vector<unsigned char> m_EncryptedSendData;
	vector<unsigned char> m_DecryptedRecvData;
	int m_SendSize;


	unsigned long long  m_BytesSizeRecieved;
	unsigned long long  m_TotalRecived;
	unsigned long long  m_CurrRecived;

};








/////////////////////////////////////////////////////////////////////////////////////
class HttpsClient : noncopyable
{
public:
	HttpsClient(EventLoop* loop,	const InetAddress& serverAddr)
		: loop_(loop)
	{
		loop->runAfter(1000, std::bind(&HttpsClient::handleTimeout, this));
		
		session_ = new SSLSession(loop, serverAddr,"ssl");
		session_->set_connected_callback(bind(&HttpsClient::onConnect, this));
		session_->set_receive_callback(bind(&HttpsClient::handledata, this, _1, _2));
		

	}


	void onConnect()
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
		session_->SSLSendData((char*)szRequest, reqStr.size());
	}

	void start()
	{
		session_->start();
	}
	int handledata(unsigned char* data, size_t datalen)
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

	void handleTimeout()
	{
		LOG_WARN << "stop";
		loop_->runAfter(1000, std::bind(&HttpsClient::handleTimeout, this));
	}

	EventLoop* loop_;
	SSLSession* session_;
};











int main(int argc, char* argv[])
{
	Logger::setLogLevel(Logger::WARN);

	EventLoop loop;
	
	const char* ip = "192.168.1.200"; //"192.168.1.200";

	uint16_t port = 443;
	InetAddress serverAddr(ip, port);

	HttpsClient client(&loop, serverAddr);
	client.start();

	loop.loop();

}

