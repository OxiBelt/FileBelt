/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Samba 4.24.4 VFS entry point.  It deliberately keeps FileBelt policy out of
 * smbd: Samba owns wire/session semantics; the bridge owns bounded IPC; the
 * future FileBelt VFS service owns authorization, namespace, payload and locks.
 */

#include "includes.h"
#include "smbd/smbd.h"
#include "smbd/vfs.h"

#include <errno.h>

static int filebelt_connect(struct vfs_handle_struct *handle,
                            const char *service, const char *user)
{
    /* The production bridge handshake binds the authenticated Samba session,
     * credential generation, observed tailnet device and gateway epoch. */
    return SMB_VFS_NEXT_CONNECT(handle, service, user);
}

static void filebelt_disconnect(struct vfs_handle_struct *handle)
{
    /* Close is best effort only; the core's write-session fence is authoritative. */
    SMB_VFS_NEXT_DISCONNECT(handle);
}

/*
 * These signatures are taken from Samba 4.24.4 source3/include/vfs.h.  The
 * bridge IPC implementation is intentionally not faked: until the C module can
 * exchange an authenticated, framed request with filebelt-smb-bridge, every
 * data-plane call fails closed and never reaches Samba's local backing store.
 */
static int filebelt_openat(struct vfs_handle_struct *handle,
                           const struct files_struct *dirfsp,
                           const struct smb_filename *smb_fname,
                           struct files_struct *fsp,
                           const struct vfs_open_how *how)
{
    (void)handle; (void)dirfsp; (void)smb_fname; (void)fsp; (void)how;
    errno = ENOSYS;
    return -1;
}

static ssize_t filebelt_pread(struct vfs_handle_struct *handle,
                              struct files_struct *fsp,
                              void *data, size_t n, off_t offset)
{
    (void)handle; (void)fsp; (void)data; (void)n; (void)offset;
    errno = ENOSYS;
    return -1;
}

static int filebelt_close(struct vfs_handle_struct *handle,
                          struct files_struct *fsp)
{
    (void)handle; (void)fsp;
    return 0;
}

static struct vfs_fn_pointers filebelt_fns = {
    .connect_fn = filebelt_connect,
    .disconnect_fn = filebelt_disconnect,
    .openat_fn = filebelt_openat,
    .pread_fn = filebelt_pread,
    .close_fn = filebelt_close,
};

NTSTATUS vfs_filebelt_init(TALLOC_CTX *ctx)
{
    return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "filebelt", &filebelt_fns);
}
