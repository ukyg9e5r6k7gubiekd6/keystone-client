#include "keystone-client.h"

int main(void)
{
	keystone_context_t context;
	enum keystone_error result;

	result = keystone_global_init();
	printf("keystone_global_init result: %d\n", result);

	/* we must initialise with false values in order keystone_start could
	 * assign default values for context */
	/* TODO: eliminate preliminary assignment - do default initialisation
	 * inside keystone_start */
	context.curl_error = NULL;
	context.json_error = NULL;
	context.keystone_error = NULL;
	context.allocator = NULL;
	result = keystone_start(&context);
	printf("keystone_start result: %d\n", result);

	result = keystone_set_debug(&context, 1);
	printf("keystone_set_debug result: %d\n", result);

	const char url[] = "http://192.168.122.216/identity/v3/auth/tokens";
	const char tenant_name[] = "admin";
	const char username[] = "admin";
	const char password[] = "secret";
	result = keystone_authenticate(&context, url, tenant_name, username,
								   password);
	printf("keystone_authenticate result: %d\n", result);

	const char *token = keystone_get_auth_token(&context);
	if (token != NULL) {
		printf("token: %s\n", token);
	}

	keystone_end(&context);
	printf("keystone_end called\n");

	keystone_global_cleanup();
	printf("keystone_global_cleanup called\n");

	return 0;
}



