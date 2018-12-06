#pragma once

#include "WtlString.h"

#ifdef __cplusplus 
extern "C"
{
#endif // __cplusplus
#include <openssl/ssl.h>    
#include <openssl/err.h> 
#ifdef __cplusplus
}
#endif // __cplusplus

#include <string>
#include <vector>
#include <map>


enum HttpStatusCode
{
	/* 1xx Infomational */
	HttpStatusContinue = 100,
	HttpStatusSwichingProtocols = 101,

	/* 2xx Succesful */
	HttpStatusOk = 200,
	HttpStatsuCreated = 201,
	HttpStatusAccepted = 202,
	HttpStatusNonAuthorizedInformation = 203,
	HttpStatusNoContent = 204,
	HttpStatusResetContent = 205,
	HttpStatusPartialContent = 206,

	/* 3xx Redirection */
	HttpStatusMultipleChoices = 300,
	HttpStatusMovedPermanetly = 301,
	HttpStatusFound = 302,
	HttpStatusSeeOther = 303,
	HttpStatusNotModified = 304,
	HttpStatusUseProxy = 305,
	HttpStatusTemporaryRedirection = 307,

	/* 4xx Client Error */
	HttpStatusBadRequest = 400,
	HttpStatusUnauthorized = 401,
	HttpStatusPaymentRequired = 402,
	HttpStatusForbidden = 403,
	HttpStatusNotFound = 404,
	HttpStatusMethodNotAllowed = 405,
	HttpStatusNotAcceptable = 406,
	HttpStatusProxyAuthenticationRequired = 407,
	HttpStatusRequestTimeOut = 408,
	HttpStatusConflict = 409,
	HttpStatusGone = 410,
	HttpStatusLengthRequired = 411,
	HttpStatusProconditionFailed = 412,
	HttpStatusRequestEntityTooLarge = 413,
	HttpStatusRequestURITooLarge = 414,
	HttpStatusUnsupportedMediaType = 415,
	HttpStatusRequestedRangeNotSatisfiable = 416,
	HttpStatusExpectationFailed = 417,

	/* 5xx Server Error */
	HttpStatusInternalServerError = 500,
	HttpStatusNotImplemented = 501,
	HttpStatusBadGateway = 502,
	HttpStatusServiceUnavaliable = 503,
	HttpStatusGatewayTimeOut = 504,
	HttpStatusHttpVersionNotSupported = 505
};


class HttpsClient
{
public:
	HttpsClient();
	//!清理打开的句柄  
	~HttpsClient();

	BOOL LogoutOfServer();

	BOOL ConnectToServer(const CString strServerUrl, const int nPort);

	void CloseServer();

	BOOL SslGetCipherAndCertification();

	int GetHttpStatusCode();
public:
	typedef std::map<std::string, std::string>  CookieContainer;
	typedef std::map<std::string, std::string>::iterator  CookieIt;
	CookieContainer m_vCookie;
	std::string m_strHeader;
	std::string m_strGetResult;
	int		m_nStatusCode; // Http返回值
	bool socketHttps(std::string host, std::string request);

	bool ExtractCookie();

	bool postData(std::string host, std::string path, std::string post_content = "");

	bool getData(std::string host, std::string pathAndparameter);
	bool getDataWithParam(std::string host, std::string path, std::string get_content = "");

	void SetCookie(std::string &strCookie);

	// 获取请求的结果
	std::string GetLastRequestResult();
protected:
	// 初始化winSocket环境  
	BOOL InitializeSocketContext();
	// 原生socket连接  
	BOOL SocketConnect();
	// SSL通信初始化  
	BOOL InitializeSslContext();
	// SSL绑定原生socket,并连接服务器  
	BOOL SslConnect();
private:
	SSL *m_ssl;
	SSL_CTX *m_sslCtx;
	long m_socketClient;
	CString cstrServerUrl;
	int m_nServerPort;
	CString cstrUserName;
	CString	cstrPassWord;
	CString m_cstrCookieUid;

	SOCKADDR_IN m_socketAddrClient;

	const SSL_METHOD* m_sslMethod;
	
	char * m_cstrSslSubject;
	char* m_cstrSslIssuer;
};

