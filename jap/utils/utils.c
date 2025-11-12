#include "utils.h"

bool CreateFileFromMemory(const wchar_t* file_path, const char* src, size_t size) {
	FILE* file = _wfopen(file_path, L"wb");
	if (!file)
		return false;

	size_t written = fwrite(src, 1, size, file);
	fclose(file);

	return written == size;
}

bool RemoveFileFromDisk(const wchar_t* file_path) {
	return _wremove(file_path) == 0;
}