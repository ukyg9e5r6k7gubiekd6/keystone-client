#include <assert.h>
#include <string.h>

#include "keystone-client.h"

/* The MIME type representing JavaScript Object Notation */
#define MIME_TYPE_JSON "application/json"
/* The content-type of the authentication requests we send */
/* Each of XML and JSON is allowed; we use JSON for brevity and simplicity */
#define KEYSTONE_AUTH_REQUEST_FORMAT MIME_TYPE_JSON
/* The content-type we desire to receive in authentication responses */
#define KEYSTONE_AUTH_RESPONSE_FORMAT MIME_TYPE_JSON
/* The portion of a JSON-encoded Keystone credentials POST body preceding the
 * username */
#define KEYSTONE_AUTH_PAYLOAD_BEFORE_USERNAME "{\"auth\": {\"identity\": \
{\"methods\": [\"password\"],\"password\": {\"user\": {\"domain\": {\"name\": \
\"Default\"},\"name\": \""
/* The portion of a JSON-encoded Keystone credentials POST body succeeding the
 * username and preceding the password */
#define KEYSTONE_AUTH_PAYLOAD_BEFORE_PASSWORD "\", \"password\": \""
/* The portion of a JSON-encoded Keystone credentials POST body succeeding the
 * password and preceding the tenant name */
#define KEYSTONE_AUTH_PAYLOAD_BEFORE_TENANT "\"}}}, \"scope\": \
{\"project\":{\"domain\":{\"name\": \"Default\"}, \"name\": \""
/* The portion of a JSON-encoded Keystone credentials POST body succeeding the
 * tenant name */
#define KEYSTONE_AUTH_PAYLOAD_END "\"}}}}"
/* Number of elements in a statically-sized array */
#define ELEMENTSOF(arr) (sizeof(arr) / sizeof((arr)[0]))

/**
 *  Service type names in Keystone's catalog of services.
 *  Order must match that in enum openstack_service.
 */
static const char *const openstack_service_names[] = {
	"identity",     /* Keystone */
	"compute",      /* Nova */
	"ec2",          /* Nova EC2 */
	"object-store", /* Swift */
	"s3",           /* Swift S3 */
	"volume",       /* Cinder */
	"image"         /* Glance */
};

/* Human-friendly names for service endpoint URL types */
static const char *const openstack_service_endpoint_url_type_friendly_names[] =
		{
	"public",
	"admin",
	"internal"
};

/**
 * Default handler for libcurl errors.
 */
static void
default_curl_error_callback(const char *curl_funcname, CURLcode curl_err)
{
	assert(curl_funcname != NULL);
	fprintf(stderr, "%s failed: libcurl error code %ld: %s\n", curl_funcname,
			(long) curl_err, curl_easy_strerror(curl_err));
}

/**
 * Default handler for Keystone errors.
 */
static void
default_keystone_error_callback(const char *keystone_operation,
								enum keystone_error keystone_err)
{
	assert(keystone_operation != NULL);
	assert(keystone_err != KSERR_SUCCESS);
	fprintf(stderr, "Keystone: %s: error %ld\n", keystone_operation,
			(long) keystone_err);
}

/**
 * Default memory [re-/de-]allocator.
 */
static void *
default_allocator(void *ptr, size_t size)
{
	if (0 == size) {
		if (ptr != NULL) {
			free(ptr);
		}
		return NULL;
	}
	if (NULL == ptr) {
		return malloc(size);
	}
	return realloc(ptr, size);
}

/**
 * To be called at start of user program, while still single-threaded.
 * Non-thread-safe and non-re-entrant.
 */
enum keystone_error
keystone_global_init(void)
{
	CURLcode curl_err;

	curl_err = curl_global_init(CURL_GLOBAL_ALL);
	if (curl_err != 0) {
		/* TODO: Output error indications about detected error in 'res' */
		return KSERR_INIT_FAILED;
	}

	return KSERR_SUCCESS;
}

/**
 * To be called at end of user program, while again single-threaded.
 * Non-thread-safe and non-re-entrant.
 */
void
keystone_global_cleanup(void)
{
	curl_global_cleanup();
}

/**
 * To be called by each thread of user program that will use this library,
 * before first other use of this library.
 * Thread-safe and re-entrant.
 */
enum keystone_error
keystone_start(keystone_context_t *context)
{
	assert(context != NULL);
	if (!context->curl_error) {
		context->curl_error = default_curl_error_callback;
	}
	if (!context->keystone_error) {
		context->keystone_error = default_keystone_error_callback;
	}
	if (!context->allocator) {
		context->allocator = default_allocator;
	}
	context->pvt.curl = curl_easy_init();
	if (NULL == context->pvt.curl) {
		/* NOTE: No error code from libcurl,
		 * so we assume/invent CURLE_FAILED_INIT */
		context->curl_error("curl_easy_init", CURLE_FAILED_INIT);
		return KSERR_INIT_FAILED;
	}

	context->pvt.auth_token = NULL;
	context->pvt.auth_payload = NULL;
	return KSERR_SUCCESS;
}

/**
 * To be called by each thread of user program that will use this library,
 * after last other use of this library.
 * To be called once per successful call to keystone_start by that thread.
 * Thread-safe and re-entrant.
 */
void
keystone_end(keystone_context_t *context)
{
	assert(context != NULL);
	assert(context->pvt.curl != NULL);

	curl_easy_cleanup(context->pvt.curl);
	context->pvt.curl = NULL;
	if (context->pvt.auth_token != NULL) {
		context->pvt.auth_token = context->allocator(context->pvt.auth_token,
													 0);
	}
	if (context->pvt.auth_payload != NULL) {
		context->pvt.auth_payload = context->allocator(
				context->pvt.auth_payload, 0);
	}
}

/**
 * Control whether a proxy (eg HTTP or SOCKS) is used to access the Keystone
 * server. Argument must be a URL, or NULL if no proxy is to be used.
 */
enum keystone_error
keystone_set_proxy(keystone_context_t *context, const char *proxy_url)
{
	CURLcode curl_err;

	assert(context != NULL);
	assert(context->pvt.curl != NULL);

	curl_err = curl_easy_setopt(context->pvt.curl, CURLOPT_PROXY,
								(NULL == proxy_url) ? "" : proxy_url);
	if (CURLE_OK != curl_err) {
		context->curl_error("curl_easy_setopt", curl_err);
		return KSERR_INVARG;
	}

	return KSERR_SUCCESS;
}

/**
 * Control verbose logging to stderr of the actions of this library and the
 * libraries it uses. Currently this enables logging to standard error of
 * libcurl's actions.
 */
enum keystone_error
keystone_set_debug(keystone_context_t *context, unsigned int enable_debugging)
{
	CURLcode curl_err;

	assert(context != NULL);
	assert(context->pvt.curl != NULL);

	context->pvt.debug = enable_debugging;

	curl_err = curl_easy_setopt(context->pvt.curl, CURLOPT_VERBOSE,
								enable_debugging ? 1 : 0);
	if (CURLE_OK != curl_err) {
		context->curl_error("curl_easy_setopt", curl_err);
		return KSERR_INVARG;
	}

	return KSERR_SUCCESS;
}

const char *
service_name(unsigned int service)
{
	assert(service < ELEMENTSOF(openstack_service_names));
	return openstack_service_names[service];
}

const char *
endpoint_url_name(unsigned int endpoint)
{
	assert(endpoint < ELEMENTSOF(
			openstack_service_endpoint_url_type_friendly_names));
	return openstack_service_endpoint_url_type_friendly_names[endpoint];
}

static size_t
process_keystone_response_headers(char *buffer, size_t size, size_t nitems,
								  void *userdata) {
/* Authentication token */
	size_t len = size * nitems;
	keystone_context_t *context = (keystone_context_t *) userdata;
	if (strstr(strtok(buffer, ":"), "X-Subject-Token")) {
		char *token = strtok(NULL, "\n");
		context->pvt.auth_token = context->allocator(context->pvt.auth_token,
													 strlen(token)
		);
		if (NULL == context->pvt.auth_token) {
			return 0; /* Allocation failed */
		}
		strcpy(context->pvt.auth_token, token);
		printf("token in process_keystone_response_headers: %s\n",
			   context->pvt.auth_token);
	}
	return len;
}

/**
 * Authenticate against a Keystone authentication service with the given tenant
 * and user names and password. This yields an authorisation token.
 */
enum keystone_error
keystone_authenticate(keystone_context_t *context, const char *url,
					  const char *tenant_name, const char *username,
					  const char *password)
{
	CURLcode curl_err;
	struct curl_slist *headers = NULL;
	size_t body_len;

	assert(context != NULL);
	assert(context->pvt.curl != NULL);
	assert(url != NULL);
	assert(tenant_name != NULL);
	assert(username != NULL);
	assert(password != NULL);

	body_len =
		strlen(KEYSTONE_AUTH_PAYLOAD_BEFORE_USERNAME)
		+ strlen(username)
		+ strlen(KEYSTONE_AUTH_PAYLOAD_BEFORE_PASSWORD)
		+ strlen(password)
		+ strlen(KEYSTONE_AUTH_PAYLOAD_BEFORE_TENANT)
		+ strlen(tenant_name)
		+ strlen(KEYSTONE_AUTH_PAYLOAD_END)
	;

	curl_err = curl_easy_setopt(context->pvt.curl, CURLOPT_URL, url);
	if (CURLE_OK != curl_err) {
		context->curl_error("curl_easy_setopt", curl_err);
		return KSERR_URL_FAILED;
	}

	curl_err = curl_easy_setopt(context->pvt.curl, CURLOPT_POST, 1L);
	if (CURLE_OK != curl_err) {
		context->curl_error("curl_easy_setopt", curl_err);
		return KSERR_URL_FAILED;
	}

	/* Append header specifying body content type (since this differs from
	 * libcurl's default) */
	headers = curl_slist_append(headers,
								"Content-Type: " KEYSTONE_AUTH_REQUEST_FORMAT);

	/* Append pseudo-header defeating libcurl's default addition of an "Expect:
	 * 100-continue" header. */
	headers = curl_slist_append(headers, "Expect:");

	/* Generate POST request body containing the authentication credentials */
	context->pvt.auth_payload = context->allocator(
		context->pvt.auth_payload,
		body_len
		+ 1 /* '\0' */
	);
	if (NULL == context->pvt.auth_payload) {
		curl_slist_free_all(headers);
		return KSERR_ALLOC_FAILED;
	}
	sprintf(context->pvt.auth_payload, "%s%s%s%s%s%s%s",
		KEYSTONE_AUTH_PAYLOAD_BEFORE_USERNAME,
		username,
		KEYSTONE_AUTH_PAYLOAD_BEFORE_PASSWORD,
		password,
		KEYSTONE_AUTH_PAYLOAD_BEFORE_TENANT,
		tenant_name,
		KEYSTONE_AUTH_PAYLOAD_END
	);

	if (context->pvt.debug) {
		fputs(context->pvt.auth_payload, stderr);
	}

	/* Pass the POST request body to libcurl. The data are not copied, so they
	 * must persist during the request lifetime. */
	curl_err = curl_easy_setopt(context->pvt.curl, CURLOPT_POSTFIELDS,
								context->pvt.auth_payload);
	if (CURLE_OK != curl_err) {
		context->curl_error("curl_easy_setopt", curl_err);
		curl_slist_free_all(headers);
		return KSERR_URL_FAILED;
	}

	curl_err = curl_easy_setopt(context->pvt.curl, CURLOPT_POSTFIELDSIZE,
								body_len);
	if (CURLE_OK != curl_err) {
		context->curl_error("curl_easy_setopt", curl_err);
		curl_slist_free_all(headers);
		return KSERR_URL_FAILED;
	}

	/* Add header requesting desired response content type */
	headers = curl_slist_append(headers,
								"Accept: " KEYSTONE_AUTH_RESPONSE_FORMAT);

	curl_err = curl_easy_setopt(context->pvt.curl, CURLOPT_WRITEFUNCTION, NULL);
	if (CURLE_OK != curl_err) {
		context->curl_error("curl_easy_setopt", curl_err);
		curl_slist_free_all(headers);
		return KSERR_URL_FAILED;
	}

	curl_err = curl_easy_setopt(context->pvt.curl, CURLOPT_HTTPHEADER, headers);
	if (CURLE_OK != curl_err) {
		context->curl_error("curl_easy_setopt", curl_err);
		curl_slist_free_all(headers);
		return KSERR_URL_FAILED;
	}

	curl_err = curl_easy_setopt(context->pvt.curl, CURLOPT_HEADERDATA,
								context);
	if (CURLE_OK != curl_err) {
		context->curl_error("curl_easy_setopt", curl_err);
		curl_slist_free_all(headers);
		return KSERR_URL_FAILED;
	}

	curl_err = curl_easy_setopt(context->pvt.curl,
								CURLOPT_HEADERFUNCTION,
								process_keystone_response_headers);
	if (CURLE_OK != curl_err) {
		context->curl_error("curl_easy_setopt", curl_err);
		curl_slist_free_all(headers);
		return KSERR_URL_FAILED;
	}

	curl_err = curl_easy_perform(context->pvt.curl);
	if (CURLE_OK != curl_err) {
		context->curl_error("curl_easy_perform", curl_err);
		curl_slist_free_all(headers);
		return KSERR_URL_FAILED;
	}

	curl_slist_free_all(headers);

	if (NULL == context->pvt.auth_token) {
		return KSERR_AUTH_REJECTED;
	}

	return KSERR_SUCCESS;
}

/**
 * Return the previously-acquired Keystone authentication token, if any.
 * If no authentication token has previously been acquired, return NULL.
 */
const char *
keystone_get_auth_token(keystone_context_t *context)
{
	assert(context != NULL);

	return context->pvt.auth_token;
}
