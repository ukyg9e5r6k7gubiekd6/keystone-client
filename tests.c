#include <string.h>

#include "keystone-client.h"

enum keystone_error
init() {
	enum keystone_error result = keystone_global_init();
	printf("keystone_global_init result: %d\n", result);
	return result;
}

enum keystone_error
start(keystone_context_t *context){
	/* we must initialise with false values in order keystone_start could
	 * assign default values for context */
	/* TODO: eliminate preliminary assignment - do default initialisation
	 * inside keystone_start */
	context->curl_error = NULL;
	context->json_error = NULL;
	context->keystone_error = NULL;
	context->allocator = NULL;
	enum keystone_error result = keystone_start(context);
	printf("keystone_start result: %d\n", result);
	return result;
}

enum keystone_error
set_debug(keystone_context_t *context){
	enum keystone_error result = keystone_set_debug(context, 1);
	printf("keystone_set_debug result: %d\n", result);
	return result;
}

enum keystone_error
authenticate(keystone_context_t *context){
	char *temp_var = NULL;
	const char *url;
	temp_var = getenv("KSTEST_ADMIN_URL");
	if (temp_var) {
		url = strcat(temp_var, "/v3/auth/tokens");
	}
	else {
		url = "http://192.168.122.216/identity/v3/auth/tokens";
	}
	const char *tenant_name;
	temp_var = getenv("OS_PROJECT_NAME");
	if (temp_var) {
		tenant_name = temp_var;
	}
	else {
		tenant_name = "admin";
	}
	const char *username;
	temp_var = getenv("KSTEST_ADMIN_USERNAME");
	if (temp_var) {
		username = temp_var;
	}
	else {
		username = "admin";
	}
	const char *password;
	temp_var = getenv("KSTEST_ADMIN_PASSWORD");
	if (temp_var) {
		password = temp_var;
	}
	else {
		password = "secret";
	}
	enum keystone_error result = keystone_authenticate(context, url,
			tenant_name, username, password);
	printf("keystone_authenticate result: %d\n", result);
	return result;
}

void print_token (keystone_context_t *context){
	const char *token = keystone_get_auth_token(context);
	if (token != NULL) {
		printf("token: %s\n", token);
	}
}

void end (keystone_context_t *context){
	keystone_end(context);
	printf("keystone_end called\n");
}

void cleanup (){
	keystone_global_cleanup();
	printf("keystone_global_cleanup called\n");
}

int main(void)
{
	keystone_context_t context;
	init();
	start(&context);
	set_debug(&context);
	authenticate(&context);
	print_token(&context);
	end(&context);
	cleanup();
	return 0;
}



