#include "include/EasyPdb.h"

#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING

#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <stdio.h>

#include "ezpdb.hpp"

extern "C" {

	int EzPdbGetRva(const char* path, const char* symname)
	{
		ez::pdb pdb = ez::pdb(path);
		if (!pdb.init())
			return 0;

		return pdb.get_rva(symname);
	}
}
