## CVE-2022-32832
#### Proof-of-concept and write-up for the CVE-2022-32832 vulnerability patched in iOS 15.6

CVE-2022-32832 is a vulnerability in the `AppleAPFSUserClient::methodDeltaCreateFinalize` external method (selector 49). Here is the decompilation pre-patch:

```cpp
__int64 __cdecl AppleAPFSUserClient::methodDeltaCreateFinalize(AppleAPFSUserClient *this, void *a2, IOExternalMethodArguments *args)
{
	void *ctx;
	__int64 result;

	ctx = this->deltaCreateCtx;
	if ( !ctx )
		return 0xE00002D8LL;
	AppleAPFSContainer::deltaCreateTeardown(ctx);
	result = 0LL;
	this->deltaCreateCtx = 0LL;
	return result;
}
```

`AppleAPFSUserClient::externalMethod` does not use any synchronisation techniques to serialise external method calls. This means that it is possible for an attacker to double-free the `delta_create_ctx_t`, and related properties, by racing two calls to `AppleAPFSUserClient::methodDeltaCreateFinalize` on the same userclient, as both will be able to call into `AppleAPFSContainer::deltaCreateTeardown` (the method responsible for freeing the `delta_create_ctx_t`) before `this->deltaCreateCtx` is set to `NULL`.

In order to trigger this, an attacker first needs to create a "delta create context" on the userclient by using the external method `AppleAPFSUserClient::methodDeltaCreatePrepare` (selector 36). This requires an unmounted volume to function, so a normal exploit flow requires the attacker to also create a target volume using the external method `AppleAPFSUserClient::methodVolumeCreate`, which requires superuser privileges. It is for this reason that Apple described the impact of the vulnerability as:

> An app with root privileges may be able to execute arbitrary code with kernel privileges

This repository includes a proof-of-concept exploit for this issue that causes a kernel panic on vulnerable macOS versions by underflowing a kernel object's reference count. This exploit must be executed as root for the reasons mentioned above.

CVE-2022-32832 was patched by adding `IOLockLock` and `IOLockUnlock` calls to `AppleAPFSUserClient::methodDeltaCreateFinalize` to protect the vulnerable code.
