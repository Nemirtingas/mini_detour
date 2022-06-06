# mini_detour

Minimalistic cross-platform detour library.
Supported platforms are:
Windows (tested on Windows >7).
Linux (tested on Ubuntu >16)
MacOS (test on High Sierra and Big Sur, since Monterey, you can't hook anymore functions cause write permission is rejected by the kernel).


MacOS new kernels now lock the memory and disallow Write+Execute rights and also disable further Execute rights on some pages. So you will have to use a tuned Kernel or some kind of kext to bypass this restriction:


TODO: Check how the executable loader creates maps, maybe we can use its function to allocate new block with RWX rights.


References:

Page lockdown: https://github.com/apple/darwin-xnu/blob/main/osfmk/vm/vm_user.c#L3287-L3300
```
kern_return_t
vm_map_exec_lockdown(
	vm_map_t        map)
{
	if (map == VM_MAP_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	vm_map_lock(map);
	map->map_disallow_new_exec = TRUE;
	vm_map_unlock(map);

	return KERN_SUCCESS;
}
```

Page protections change: https://github.com/apple/darwin-xnu/blob/main/osfmk/vm/vm_map.c#L5961-L5967
```
		if (map->map_disallow_new_exec == TRUE) {
			if ((new_prot & VM_PROT_EXECUTE) ||
			    ((current->protection & VM_PROT_EXECUTE) && (new_prot & VM_PROT_WRITE))) {
				vm_map_unlock(map);
				return KERN_PROTECTION_FAILURE;
			}
		}
```
