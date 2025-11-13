#include "utils/utils.h"
#include "vuln/vuln.h"


int main() {
	log_set_level(LOG_TRACE);

	const wchar_t* vuln_driver_path = L"C:\\temp\\temp.sys";
	const wchar_t* vuln_driver_name = L"tempdrv";

	TryInitVuln(vuln_driver_path, vuln_driver_name);

	return 0;
}