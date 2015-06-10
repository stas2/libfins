#include <fins.h>
#include <stdio.h>
#include <sys/time.h>

int main()
{
	int rc;

	// create context
	struct fins_t *ctxt = fins_new_tcp("127.0.0.1", 9600);
	if (!ctxt) {
		perror("Could not create context");
		return 1;
	}

	// configure response timeout
	struct timeval responseTimeoutValue = {1, 500000};	// 1.5 seconds
	fins_set_response_timeout(ctxt, &responseTimeoutValue);

	// enable debug output
	fins_set_debug(ctxt, 1);

	rc = fins_connect(ctxt);
	if (rc != 0) {
		perror("Could not connect to the server");
		fins_free(ctxt);
		return 1;
	}

	const int type = 0x82;	// D registers
	const int addr = 202;	// example address
	unsigned short data[2];	// buffer to read to
	// number of registers to read
	const int size = sizeof(data) / sizeof(data[0]);

	// read data from the server
	rc = fins_read(ctxt, type, addr, size, data);
	if (rc != size) {
		perror("Error reading data");
		fins_close(ctxt);
		fins_free(ctxt);
		return 1;
	}

	printf("Read data: %04x %04x\n", data[0], data[1]);

	// read data from the server
	rc = fins_write(ctxt, type, addr, size, data);
	if (rc != size) {
		perror("Error writing data");
		fins_close(ctxt);
		fins_free(ctxt);
		return 1;
	}

	fins_close(ctxt);
	fins_free(ctxt);
	return 0;
}

