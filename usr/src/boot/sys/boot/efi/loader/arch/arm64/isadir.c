#include <stand.h>

_Bool has_boot_services = 1;

void
bi_isadir(void)
{
	int rc;

	rc = setenv("ISADIR", "aarch64", 1);
	if (rc != 0) {
		printf("Warning: failed to set ISADIR environment "
		    "variable: %d\n", rc);
	}
}
