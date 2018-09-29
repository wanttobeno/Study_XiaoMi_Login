
#include <conio.h> // _getch
#include <ctype.h> 

#include <Windows.h>
#include "HttpsClient.h"

#include "Transcode.h"
#include "md5.h"
#include "UrlCode.h"
#include "jsoncpp/json.h"

struct JSP_VER
{
	//std::string deviceType;
	//std::string dataCenter;
	//std::string locale;
	//std::string region;
	std::string callback;
	std::string sid;
	std::string qs;
	std::string _sign;
	std::string serviveParam;
	//std::string loginMethods;
	std::string captCode; // 验证码
	JSP_VER()
	{
		//this->deviceType = "PC";
		//this->dataCenter = "c3";
		//this->locale = "zh_CN";
		//this->region = "CN";
		this->sid = "passport";
		this->serviveParam = "%7B%22checkSafePhone%22%3Afalse%7D";//"{\"checkSafePhone\":false}";
	}
};

const char* g_Host = "account.xiaomi.com";
const char* g_Url = "https://account.xiaomi.com/";

// 小米账户和密码
const char* g_username = NULL;
const char* g_userpass = NULL;

void Init_JSP_VER(std::string &strResult, JSP_VER &jspver);
bool GetVerificationCode(HttpsClient &client, JSP_VER &jspver);

// 定义64位整形
#if defined(_WIN32) && !defined(CYGWIN)
typedef __int64 int64_t;
#else
typedef long long int64t;
#endif  // _WIN32

// 获取系统的当前时间，单位微秒(us)
int64_t GetSysTimeMicros()
{
#ifdef _WIN32
	// 从1601年1月1日0:0:0:000到1970年1月1日0:0:0:000的时间(单位100ns)
#define EPOCHFILETIME   (116444736000000000UL)
	FILETIME ft;
	LARGE_INTEGER li;
	int64_t tt = 0;
	GetSystemTimeAsFileTime(&ft);
	li.LowPart = ft.dwLowDateTime;
	li.HighPart = ft.dwHighDateTime;
	// 从1970年1月1日0:0:0:000到现在的微秒数(UTC时间)
	tt = (li.QuadPart - EPOCHFILETIME) / 10;
	return tt;
#else
	timeval tv;
	gettimeofday(&tv, 0);
	return (int64_t)tv.tv_sec * 1000000 + (int64_t)tv.tv_usec;
#endif // _WIN32
	return 0;
}

void GetMoveUrl(HttpsClient &client, std::string &strMove);
void GetMd5String(std::string& out, const char* pInData)
{
	char* pMd5 = MD5String((char*)pInData);
	strupr(pMd5);
	out = pMd5;
	free(pMd5);
	pMd5 = NULL;
}

int GetInitCookie(HttpsClient &client);

bool PraseLoginJson(HttpsClient &client, std::wstring& wDesc);

bool DoLogin(JSP_VER &jspver, std::string strMd5, HttpsClient &client);

void InputPassWord(std::string& strMd5);

int main(int argc, char* argv)
{
	WSADATA wsaData;
	WORD wVersion = MAKEWORD(2, 2);
	WSAStartup(wVersion, &wsaData);

	HttpsClient client;
	if (client.ConnectToServer("account.xiaomi.com", 443) == false)
		return -1;

	if (GetInitCookie(client) < 0)
		return -2;

	JSP_VER jspver;
	std::string strResult = client.GetLastRequestResult();
	Init_JSP_VER(strResult, jspver);
	GetVerificationCode(client, jspver);

	std::string strMd5;
	do
	{
		char name[16] = { 0 };
		printf("输入用户名:\n");
		scanf("%s", &name);
		g_username = name;
		InputPassWord(strMd5);

		if (DoLogin(jspver, strMd5, client) == false)
		{
			printf("登录包错误！\n");
			break;
		}

		std::wstring wDesc;
		PraseLoginJson(client,wDesc);

		if (wcscmp(wDesc.c_str(), L"成功") == 0)
		{
			printf("输入q退出\n");
			int ch;
			do
			{
				ch = _getch();
				if (ch == 'q' || ch == 'Q')
					break;
			} while (1);
			break;
		}
		else
		{
			printf("输入q退出,其它键重新登录\n");
			int ch;
			ch = _getch();
			if (ch == 'q' || ch == 'Q')
				break;
			else
			{
				GetVerificationCode(client, jspver);
				continue;
			}
		}
	} while (1);
	return 0;
}

void Init_JSP_VER(std::string &strResult, JSP_VER &jspver)
{
	const char* pData = strResult.c_str();
	char* pFlag1 = "var JSP_VAR=";
	char* pFlag2 = "var PAGE_VAR=";
	std::size_t nPosStart = strResult.find(pFlag1);
	std::size_t nPosEnd = strResult.find(pFlag2);

	do
	{
		if (nPosStart == std::string::npos || nPosEnd == std::string::npos)
			break;
		std::string strJSP_VAR;
		strJSP_VAR.append(pData + nPosStart + strlen(pFlag1), nPosEnd - nPosStart - strlen(pFlag1) - 1);

		const char* pJsp = strJSP_VAR.c_str();
		const char* pLine = NULL;
		const char* pFenHao = NULL;
		const char* pDouHao = NULL;
		const char* pEnd = NULL;
		pEnd = strstr(pJsp, "loginMethods");
		do
		{
			pLine = strstr(pJsp, "\n");
			if (pLine == NULL)
				break;
			pFenHao = strstr(pLine + 1, ":");
			if (pFenHao == NULL)
				break;
			pDouHao = strstr(pFenHao + 1, ",");
			if (pDouHao == NULL)
				break;
			if (strncmp(pLine + 3, "callback", strlen("callback")) == 0)
			{
				std::string str;
				str.append(pFenHao + 2, pDouHao - pFenHao - 3);
				// 需要URL处理
				str = UrlCode::Encode(str);
				const char* p = str.c_str();
				jspver.callback = str;
			}
			if (strncmp(pLine + 3, "qs:", strlen("qs:")) == 0)
			{
				std::string str;
				str.append(pFenHao + 2, pDouHao - pFenHao - 3);
				// 需要URL处理
				str = UrlCode::Encode(str);
				const char* p = str.c_str();
				jspver.qs = str;
			}
			if (strncmp(pLine + 3, "\"_sign", strlen("\"_sign")) == 0)
			{
				std::string str;
				str.append(pFenHao + 2, pDouHao - pFenHao - 3);
				// 需要URL处理
				str = UrlCode::Encode(str);
				const char* p = str.c_str();
				jspver._sign = str;
			}
			pJsp = pDouHao + 1;
		} while (pJsp < pEnd);
	} while (0);
}

bool GetVerificationCode(HttpsClient &client, JSP_VER &jspver)
{
	__int64 dwTime = GetSysTimeMicros() / 1000;
	char szNum[14] = { 0 };
	_i64toa(dwTime, szNum, 10);
	std::string getCode = "/pass/getCode?icodeType=login&";
	getCode.append(szNum);

	if (client.getData2("account.xiaomi.com", getCode))
	{
		std::string strResult = client.GetLastRequestResult();
		int nLen = strResult.length();
		const char* pCaptcha = strResult.c_str();
		FILE* pFile = _wfopen(L"D://captCode.jpg", L"wb");
		if (pFile)
		{
			fwrite(pCaptcha + 5, 1, strResult.length() - 5, pFile);
			fclose(pFile);
			printf("请输入验证码(D:\\captCode.jpg):\n");
			char buf[64] = { 0 };
			scanf("%s", &buf);
			jspver.captCode = buf;
			return true;
		}
		else
		{
			printf("写入验证码文件失败\n");
			return false;
		}
	}
}

void GetMoveUrl(HttpsClient &client, std::string &strMove)
{
	if (client.GetHttpStatusCode() == HttpStatusFound)
	{
		std::string strResult = client.GetLastRequestResult();
		const char* pResult = strResult.c_str();
		const char* pHttps = strstr(pResult, "https://");
		const char* pEnd = strstr(pResult, "\">here");
		if (pHttps && pEnd)
		{
			strMove.append(pHttps, pEnd - pHttps);
		}
	}
}

int GetInitCookie(HttpsClient &client)
{
	if (client.getData("account.xiaomi.com", "/pass/auth/security/home") == false)
		return -2;
	std::string strMove;
	GetMoveUrl(client, strMove);
	std::string strPath = "/pass/serviceLogin";
	if (!strMove.empty())
	{
		int nLen = strlen(g_Url);
		strPath.clear();
		strPath.append(strMove.c_str() + nLen - 1, strMove.length() - nLen + 1);
	}

	if (client.getData2("account.xiaomi.com", strPath) == false)
		return -3;
}

bool PraseLoginJson(HttpsClient &client, std::wstring& wDesc)
{
	std::string strResult = client.GetLastRequestResult();
	const char* pResult = strResult.c_str();
	const char* pJsonHeader = "&&&START&&&";
	const char* pFind = strstr(pResult, pJsonHeader);
	if (pFind == NULL)
	{
		printf("\n您的操作频率过快，请稍后再试。\n");
		return false;
	}
	Json::Reader reader;
	Json::Value root;
	const char* pJson = pFind + strlen(pJsonHeader);
	if (reader.parse(pJson, root) == false)
	{
		printf("\n&&&START&&& JSON FAILED!\n");
		return false;
	}
	std::string desc;
	std::string location;
	std::string captchaUrl; // 验证码
	std::string d;//deviceId
	std::string passToken;
	std::string ssecurity;
	std::string nonce;
	std::string cUserId;
	std::string psecurity;
	std::string qs;
	int securityStatus = 0;
	int pwd = 1;
	int userId = 0;
	if (!root["desc"].isNull())
	{
		desc = root["desc"].asString();
		Transcode::UTF8_to_Unicode(desc.c_str(), desc.length(), wDesc);
		std::string str;
		Transcode::Unicode_to_ANSI(wDesc.c_str(), str);
		printf("\n\t登录结果: %s\n\n", str.c_str());
	}

	if (!root["location"].isNull())
		location = root["location"].asString();

	if (!root["captchaUrl"].isNull()) // 验证码地址
		captchaUrl = root["captchaUrl"].asString();

	if (!root["d"].isNull())
		d = root["d"].asString();
	if (!root["ssecurity"].isNull())
		ssecurity = root["ssecurity"].asString();
	if (!root["nonce"].isNull())
		nonce = root["nonce"].asString();
	if (!root["cUserId"].isNull())
		cUserId = root["cUserId"].asString();
	if (!root["psecurity"].isNull())
		psecurity = root["psecurity"].asString();
	if (!root["qs"].isNull())
		qs = root["qs"].asString();
	// 整数类型
	if (!root["securityStatus"].isNull())
		securityStatus = root["securityStatus"].asInt();

	if (!root["pwd"].isNull())
		pwd = root["pwd"].asInt();
	if (!root["userId"].isNull())
		userId = root["userId"].asInt();
	return true;
}

bool DoLogin(JSP_VER &jspver, std::string strMd5, HttpsClient &client)
{
	std::string strPostData;
	strPostData.append("_json=true");
	strPostData.append("&callback=");
	strPostData.append(jspver.callback);

	strPostData.append("&sid=passport");

	strPostData.append("&qs=");
	strPostData.append(jspver.qs);

	strPostData.append("&_sign=");
	strPostData.append(jspver._sign);

	strPostData.append("&serviceParam=%7B%22checkSafePhone%22%3Afalse%7D");

	// 填写验证码
	if (jspver.captCode.length())
	{
		strPostData.append("&captCode=");
		strPostData.append(jspver.captCode);
		jspver.captCode.clear();
	}

	strPostData.append("&user=");
	strPostData.append(g_username);
	strPostData.append("&hash=");
	strPostData.append(strMd5);


	std::string  path = "/pass/serviceLoginAuth2?_dc=";
	__int64 dwTime = GetSysTimeMicros() / 1000;
	char szNum[14] = { 0 };
	_i64toa(dwTime, szNum, 10);
	path.append(szNum);
	if (client.postData("account.xiaomi.com", path, strPostData) == false)
	{
		printf("\nPost Data FAILED!\n");
		return false;
	}
	return true;
}

void InputPassWord(std::string &strMd5)
{
	char pass[16] = { 0 };
	int i = 0;
	int ch = 0;
	printf("输入密码:\n");

	while (1) {
		ch = getch();
		if (ch == 13 || i >= 39) break;
		switch (ch) {
		case 27:
			cprintf("\rPassword: %40s", " ");
			cprintf("\rPassword: ");
			i = 0; pass[i] = 0;
			break;
		case 8:
			if (i > 0) {
				i--;
				pass[i] = 0;
				cprintf("\b \b");
			}
			break;
		default:
			pass[i] = ch;
			i++;
			pass[i] = 0;
			cprintf("*");
			break;
		}
	}
	GetMd5String(strMd5, pass);
}
