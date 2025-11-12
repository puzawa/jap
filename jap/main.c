#include "utils/utils.h"

int main() {
	log_set_level(LOG_TRACE);
	log_add_fp(stdout, LOG_TRACE);

	return 0;
}