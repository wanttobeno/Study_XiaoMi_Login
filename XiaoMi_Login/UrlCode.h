#pragma once
#include <string>

class UrlCode
{
public:
	UrlCode();
	~UrlCode();

	static std::string Encode(const std::string& str);

	static std::string UrlDecode(const std::string& str);

};


