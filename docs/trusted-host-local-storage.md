> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# Dedicated local authority storage

The `.431` assembly verified a practical storage route without host-root access
or changing either shared homelab filesystem: an isolated, user-owned KVM guest
with a new **1 GiB ext4 image with fs-verity enabled**. It is a storage asset,
not a running Serverware authority or accepted pilot.

## Observed results

| Operation | Actual result |
| --- | --- |
| First boot, create/fsync a new file | Passed |
| Read real inode generation | Passed, positive generation |
| Enable and measure kernel fs-verity | Passed, SHA-256 digest returned |
| Freeze file, no-replace publish directory, then freeze directory | Passed |
| Attempt file write and unlink | Both refused with `EPERM` |
| Unmount and power off | Clean success |
| Second boot with read-only block device and mount | Same generation, bytes, verity digest and immutable flags verified |

The first guest ran for about 3.4 seconds wall-clock; the read-only persistence
boot took about 2.6 seconds. Both the inner diagnostic result and outer QEMU
exit were zero. This is not a benchmark or a successful signed package install.

The guest had one vCPU, 512 MiB RAM, no network, no host filesystem sharing,
no monitor, and QEMU seccomp restrictions. A transient user scope requested
one-CPU/1-GiB/32-task limits and an outer 60-second deadline. Both scopes are now
inactive; no persistent VM service was created. The host user already had KVM
access. Guest root did not grant or require host-root access.

QEMU `8.2.2` and two missing libraries were downloaded as exact Ubuntu packages
and extracted only into the task directory; nothing was installed into the host
OS. Kernel `6.8.0-138-generic`, BusyBox and the small diagnostic programs formed
the boot inputs. Package hashes matched the local trusted APT metadata. This is
not a secure-boot, independent-attestation or hardware-key custody claim.

See the [QEMU invocation documentation](https://www.qemu.org/docs/master/system/invocation.html)
for the isolation/boot options and the [kernel fs-verity API](https://docs.kernel.org/filesystems/fsverity.html)
for the file-protection primitives. The actual commands and outputs, rather
than those reference pages alone, establish the observations above.

## Retained asset

The private durable directory is:

```text
/home/catchplate/codex-offload/serverware/development-pilots/17ab194b/authority-vm/6.8.0-138-431/
```

It retains `authority.ext4`, both initramfs images, kernel/QEMU packages and
extracted tools, diagnostic sources/binaries, exact one-attempt commands and
logs. The directory is mode0700 and disk image0600. The disk contains only
public diagnostic data, no keys or credentials. Its SHA-256 after both boots is
`c6c74b565fb24449bdfa70fd6ae36bfddddc36cbade60f0c55014dbb1e564e1e`.

Original commands retain their exact task-directory paths and one-attempt
guards. Do not blindly rerun the initialization probe on this initialized disk.
Retain the immutable diagnostic generation; actual authority installation must
use its own absent destination and genuine signed inputs. No shared cache,
image, volume or other user's data was removed.

## Remaining integration

The shared host ext4 probes still refuse fs-verity; nothing enabled it there.
The successful guest resolves the **dedicated-filesystem feasibility** issue,
not the entire deployment. Serverware/Python authority runtimes, protected
identities, networking and database authentication have not been installed into
this guest. Genuine complete-closure/rootfs-enforcement evidence and actual
signed installation remain necessary. Continue with
[local installation](trusted-host-local-installation.md) and
[policy commissioning](pilot-commissioning.md); no pilot URL is ready yet.
