#include "muduo/net/TcpClient.h"
#include "muduo/base/Logging.h"
#include "muduo/net/EventLoop.h"
#include "muduo/net/InetAddress.h"
#include "muduo/net/TcpServer.h"
#include "cert.h"


// #include "TcpClient.h"
// #include "Logging.h"
// #include "EventLoop.h"
// #include "InetAddress.h"
// #include "TcpServer.h"

#include <utility>

#include <stdio.h>
//#include <unistd.h>

#include "openssl/ssl.h"
#include "openssl/err.h"
#include <vector>
#include <functional>




enum OVERLAPPED_TYPE
{
	RECV = 0,
	SEND = 1
};




using namespace muduo;
using namespace muduo::net;
using namespace std;


class SSLServer : noncopyable
{
public:

	SSLServer(EventLoop* loop,
		const InetAddress& serverAddr,
		const string& name
	)
	: server_(loop, serverAddr, name)
	{
		m_EncryptedSendData.resize(1024 * 10);
		m_DecryptedRecvData.resize(1024 * 10);
		m_CurrRecived = 0;
		m_BytesSizeRecieved = 0;
		m_TotalRecived = 0;
		m_Handshaked = false;

		server_.setConnectionCallback(std::bind(&SSLServer::onServerConnection, this, _1));
		server_.setMessageCallback(std::bind(&SSLServer::onMessage, this, _1, _2, _3));



	}


	void start()
	{
		server_.start();
	}

	void stop()
	{
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
			m_conn = conn;
			conn->setTcpNoDelay(true);
			LOG_WARN << "connected";
			ssl_accept();
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
		SSLProcessingRecv(buf->peek(), datalen);
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

	
	int ssl_accept()
	{
		init_ssl();
		CreateServerSSLContext();
		SSL_set_accept_state(m_Ssl);
		SSLProcessingAccept();
		return 1;
	}

	void SSLProcessingAccept()
	{
		int ret;
		int ssl_error;
		
		int dwBytesSizeRecieved = 0;

		do
		{
			ret = SSL_read(m_Ssl, m_DecryptedRecvData.data(), m_DecryptedRecvData.size());
			ssl_error = SSL_get_error(m_Ssl, ret);

			if (IsSSLError(ssl_error))
				close_session();

			if (ret > 0)
				dwBytesSizeRecieved += ret;
		} while (ret > 0);

		
		if (SSL_is_init_finished(m_Ssl))
		{
			m_Handshaked = true;
			SSLReceiveData();//receive data from ssl sockets
		}
		
		SSLProcessingSend();
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
		printf("m_CurrRecived:%d ",m_CurrRecived);
		printf("m_TotalRecived:%d\n ",m_TotalRecived);
		
		if (m_SSL_receive_callback)
			m_SSL_receive_callback(m_DecryptedRecvData.data(), m_DecryptedRecvData.size());
	}


	void SSLProcessingSend()
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
	
	void init_ssl()
	{
		SSL_load_error_strings();
		SSL_library_init();

		OpenSSL_add_all_algorithms();
		ERR_load_BIO_strings();
	}
	
	void CreateClientSSLContext()
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
	
	void CreateServerSSLContext()
	{
		m_SslCtx = SSL_CTX_new(SSLv23_server_method());
		SSL_CTX_set_verify(m_SslCtx, SSL_VERIFY_NONE, nullptr);


		SetSSLCertificate();

		m_Ssl = SSL_new(m_SslCtx);
		//SSL_set_verify(ssl, SSL_VERIFY_NONE, nullptr);

		m_Bio[SEND] = BIO_new(BIO_s_mem());
		m_Bio[RECV] = BIO_new(BIO_s_mem());
		SSL_set_bio(m_Ssl, m_Bio[RECV], m_Bio[SEND]);
	}
	
	void SetSSLCertificate()
	{
		int length = strlen(server_cert_key_pem);
		BIO *bio_cert = BIO_new_mem_buf((void*)server_cert_key_pem, length);
		X509 *cert = PEM_read_bio_X509(bio_cert, nullptr, nullptr, nullptr);
		EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio_cert, 0, 0, 0);


		int ret = SSL_CTX_use_certificate(m_SslCtx, cert);
			
		if (ret != 1)
			;

		ret = SSL_CTX_use_PrivateKey(m_SslCtx, pkey);

		if (ret != 1)
			;

		X509_free(cert);
		EVP_PKEY_free(pkey);
		BIO_free(bio_cert);
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
	TcpServer server_;
	
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
class HttpsServer : noncopyable
{
public:
	HttpsServer(EventLoop* loop, const InetAddress& serverAddr, const string& nameArg)
		: loop_(loop)
	{
		//loop->runEvery(1000, std::bind(&HttpsServer::handleTimeout, this));

		session_ = new SSLServer(loop, serverAddr, "ssl");
		session_->set_connected_callback(bind(&HttpsServer::onConnect, this));
		session_->set_receive_callback(bind(&HttpsServer::handledata, this, _1, _2));
	}


	void onConnect()
	{
		LOG_WARN << "connected";
	}

	void start()
	{
		session_->start();
	}
	int handledata(unsigned char* data, size_t datalen)
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
		session_->SSLSendData((char*)szRequest, reqStr.size());
		//session_->close();
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
		loop_->runAfter(1000, std::bind(&HttpsServer::handleTimeout, this));
	}

	EventLoop* loop_;
	SSLServer* session_;
};











int main(int argc, char* argv[])
{
	Logger::setLogLevel(Logger::WARN);

	EventLoop loop;

	const char* ip = "0.0.0.0"; //"192.168.1.200";

	int16_t port = 1443;
	InetAddress listenAddr(ip, port);
	

	HttpsServer server(&loop, listenAddr, "http server");
	server.start();

	loop.loop();

}

