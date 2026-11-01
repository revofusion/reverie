/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Import supervisor-owned OFDs for shared mappings and guest-context flock.
//! Neither operation relies on procfs visibility, shared PID/network namespaces,
//! or persistent descriptors in a guest descriptor table.

use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;

use reverie::Stack;

use super::*;

// Linux's 64-bit msghdr/cmsghdr layout. Integer fields keep guest addresses
// distinct from host pointers (and keep the injection future Send).
const CONTROL_LEN: usize = 24;
const RIGHTS_LEN: usize = 20;
const PIDFD_THREAD: u32 = 0x80;

enum ImportedOperation {
    Map {
        address: Option<u64>,
        length: usize,
        prot: i32,
        flags: i32,
    },
    Flock(i32),
}

// Cancellation after an injected allocation may leave its result unknown, and
// a dying thread can share its descriptor table with a surviving sibling. Do
// not let that sibling resume with transport state: use the existing whole-tree
// failure owner, which also prevents descriptor-number reuse during cleanup.
struct TransportGuard {
    session: Arc<FatalSession>,
    origin: BackendFailure,
    armed: bool,
}

impl Drop for TransportGuard {
    fn drop(&mut self) {
        if self.armed {
            self.session.fail_at(
                self.origin,
                anyhow::anyhow!("native descriptor transport interrupted before cleanup").into(),
            );
        }
    }
}

fn open_pidfd(tid: Tid, flags: u32) -> Result<OwnedFd, Errno> {
    let fd = Errno::result(unsafe { libc::syscall(libc::SYS_pidfd_open, tid.as_raw(), flags) })?;
    // SAFETY: a successful pidfd_open returns a newly owned host descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

pub(super) fn task_pidfd(tid: Tid, pid: Pid) -> Result<OwnedFd, Errno> {
    // Never substitute the group leader's table for an unshared thread table.
    match open_pidfd(tid, PIDFD_THREAD) {
        Err(Errno::EINVAL) if tid == pid => open_pidfd(tid, 0),
        other => other,
    }
}

fn send_backing(socket: &OwnedFd, backing: BorrowedFd<'_>) -> Result<(), Errno> {
    let mut byte = 0u8;
    let mut iov = libc::iovec {
        iov_base: (&mut byte as *mut u8).cast(),
        iov_len: 1,
    };
    let mut control = [0u64; CONTROL_LEN / 8];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = CONTROL_LEN;
    // SAFETY: the aligned control buffer has CMSG_SPACE(sizeof(int)) bytes;
    // every pointer is local and remains live through the synchronous send.
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = RIGHTS_LEN;
        libc::CMSG_DATA(header)
            .cast::<i32>()
            .write(backing.as_raw_fd());
    }
    loop {
        let result = Errno::result(unsafe {
            libc::sendmsg(
                socket.as_raw_fd(),
                &message,
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        });
        match result {
            Err(Errno::EINTR) => continue,
            Ok(1) => return Ok(()),
            Ok(_) => return Err(Errno::EIO),
            Err(error) => return Err(error),
        }
    }
}

impl<L: Tool + 'static> TracedTask<L> {
    /// Transport syscalls belong to the backend, not to the application's
    /// syscall stream. Preserve each result without retrying an allocation or
    /// close whose effects may already have occurred.
    async fn inject_descriptor_call(
        &mut self,
        nr: Sysno,
        args: SyscallArgs,
    ) -> Result<i64, Errno> {
        // A first injection consumes the pending entry and can otherwise leave
        // its result in the application's register frame. Backend transport
        // must preserve that frame even on a recoverable kernel errno. Do not
        // resurrect pending_syscall: its physical seccomp entry was consumed.
        let registers = match self.assume_stopped().getregs() {
            Ok(registers) => registers,
            Err(error) => self.abort(Err(error.into())).await,
        };
        let native = NativeCallContext::internal();
        let outcome = self.do_inject_outcome_with(nr, args, &native).await;
        let result = match host_linux::guest_result(outcome) {
            Ok(result) => result,
            Err(error) => self.abort(Err(error)).await,
        };
        if let Err(error) = self.assume_stopped().setregs(&registers) {
            self.abort(Err(error.into())).await;
        }
        result
    }

    pub(super) async fn import_shared_backing(
        &mut self,
        backing: OwnedFd,
        address: Option<u64>,
        length: usize,
        prot: i32,
        flags: i32,
    ) -> Result<u64, reverie::Error> {
        if !self.supports_shared_backing() {
            return Err(Errno::ENOSYS.into());
        }
        let supported = libc::MAP_SHARED | libc::MAP_FIXED | libc::MAP_FIXED_NOREPLACE;
        if flags & !supported != 0 || prot & !(libc::PROT_READ | libc::PROT_WRITE) != 0 {
            return Err(Errno::ENOSYS.into());
        }
        if flags & libc::MAP_SHARED == 0 || length == 0 {
            return Err(Errno::EINVAL.into());
        }
        let rounded = length.checked_add(4095).ok_or(Errno::ENOMEM)? & !4095;
        let file = std::fs::File::from(backing);
        let metadata = file
            .metadata()
            .map_err(|error| Errno::new(error.raw_os_error().unwrap_or(libc::EIO)))?;
        if !metadata.is_file() || metadata.len() < rounded as u64 {
            return Err(Errno::EINVAL.into());
        }
        let backing: OwnedFd = file.into();

        self.with_imported_descriptor(
            backing.as_fd(),
            ImportedOperation::Map {
                address,
                length,
                prot,
                flags,
            },
        )
        .await?
        .map(|address| address as u64)
        .map_err(Into::into)
    }

    pub(super) async fn execute_pinned_flock(
        &mut self,
        pin: &reverie::PinnedFlock,
        operation: i32,
    ) -> Result<i64, reverie::Error> {
        if !self.supports_shared_backing() {
            return Err(Errno::ENOSYS.into());
        }
        let kind = operation & !libc::LOCK_NB;
        if !matches!(kind, libc::LOCK_SH | libc::LOCK_EX | libc::LOCK_UN)
            || (kind != libc::LOCK_UN && operation & libc::LOCK_NB == 0)
        {
            return Err(Errno::EINVAL.into());
        }
        let stopped = self.assume_stopped();
        self.authenticate_native_fact_stop(&stopped)
            .map_err(|error| anyhow::anyhow!("flock requires an owned stop: {error:?}"))?;
        let fd = pin.facts().fd;
        // The usual case needs no socketpair, SCM_RIGHTS, or temporary guest
        // descriptors. Prove the original slot still names the retained OFD
        // in this serialized stop; fd reuse falls through to the import path.
        let same = unsafe {
            libc::syscall(
                libc::SYS_kcmp,
                self.tid.as_raw(),
                libc::getpid(),
                0,
                fd as libc::c_ulong,
                pin.as_fd().as_raw_fd() as libc::c_ulong,
            )
        };
        if same == 0 {
            return self.inject_descriptor_call(
                Sysno::flock,
                SyscallArgs::new(fd as usize, operation as usize, 0, 0, 0, 0),
            ).await.map_err(Into::into);
        }
        match self
            .with_imported_descriptor(pin.as_fd(), ImportedOperation::Flock(operation))
            .await
        {
            Ok(result) => result.map_err(Into::into),
            // A signal before a transport instruction leaves the original
            // application call unexecuted and may be delivered/restarted.
            Err(error @ reverie::Error::Errno(Errno::ERESTARTSYS)) => Err(error),
            // In particular, sendmsg/recvmsg EAGAIN is NOT flock contention.
            // Resource/custody failures must not become application lock errno.
            Err(error) => Err(anyhow::anyhow!("pinned flock transport failed: {error}").into()),
        }
    }

    async fn with_imported_descriptor(
        &mut self,
        backing: BorrowedFd<'_>,
        operation: ImportedOperation,
    ) -> Result<Result<i64, Errno>, reverie::Error> {
        let stopped = self.assume_stopped();
        self.authenticate_native_fact_stop(&stopped)
            .map_err(|error| anyhow::anyhow!("native import requires an owned stop: {error:?}"))?;
        let pidfd = task_pidfd(self.tid, self.pid())?;
        let mut stack = self.stack().await;
        let pair = stack.reserve::<[i32; 2]>();
        let data = stack.reserve::<u8>();
        let control = stack.reserve::<[u64; 3]>();
        let iov = stack.push([data.as_raw() as u64, 1]);
        let message = stack.push([
            0u64,
            0,
            iov.as_raw() as u64,
            1,
            control.as_raw() as u64,
            CONTROL_LEN as u64,
            0,
        ]);
        let _scratch = stack.commit()?;
        let mut transport = TransportGuard {
            session: self.fatal_session(),
            origin: BackendFailure {
                pid: self.pid(),
                tid: self.tid,
                phase: "ptrace native descriptor transport",
            },
            armed: true,
        };
        if let Err(error) = self
            .inject_descriptor_call(
                Sysno::socketpair,
                SyscallArgs::new(
                    libc::AF_UNIX as usize,
                    (libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK) as usize,
                    0,
                    pair.as_raw(),
                    0,
                    0,
                ),
            )
            .await
        {
            transport.armed = false;
            return Err(error.into());
        }
        // A failed read after successful allocation must terminate the run:
        // returning an errno would resume with unknown private descriptors.
        let pair: [i32; 2] = self.memory().read_value(pair).map_err(|error| {
            anyhow::anyhow!("cannot recover native transport socketpair: {error}")
        })?;
        let mut imported = None;
        let mut imported_descriptor_unknown = false;
        let task = &mut *self;
        let imported_slot = &mut imported;
        let unknown_import = &mut imported_descriptor_unknown;
        let result: Result<Result<i64, Errno>, reverie::Error> = async move {
            let fd = Errno::result(unsafe {
                libc::syscall(libc::SYS_pidfd_getfd, pidfd.as_raw_fd(), pair[0], 0)
            })?;
            // SAFETY: pidfd_getfd duplicates into the supervisor, not the guest.
            let sender = unsafe { OwnedFd::from_raw_fd(fd as i32) };
            send_backing(&sender, backing)?;
            *unknown_import = true;
            let received_bytes = task
                .inject_descriptor_call(
                    Sysno::recvmsg,
                    SyscallArgs::new(
                        pair[1] as usize,
                        message.as_raw(),
                        (libc::MSG_CMSG_CLOEXEC | libc::MSG_DONTWAIT) as usize,
                        0,
                        0,
                        0,
                    ),
                )
                .await;
            if !task.last_injection_ran {
                // A signal stopped the call before its instruction. Nothing
                // was installed; cleanup can return the original interruption.
                *unknown_import = false;
            }
            if received_bytes? != 1 {
                return Err(anyhow::anyhow!("invalid native descriptor transport payload").into());
            }
            let received = task.memory().read_value(message).map_err(|error| {
                anyhow::anyhow!("cannot recover native transport receive result: {error}")
            })?;
            if received[6] as i32 & libc::MSG_CTRUNC != 0 {
                // The buffer fits the single descriptor sent above. Linux
                // discards that one right if the guest's fd table is full.
                *unknown_import = false;
                return Err(Errno::EMFILE.into());
            }
            // Only our stopped task can access this fresh socketpair. One
            // complete SCM_RIGHTS packet installs exactly one descriptor.
            let rights: [u64; 3] = task.memory().read_value(control).map_err(|error| {
                anyhow::anyhow!("cannot recover imported native descriptor: {error}")
            })?;
            if rights[0] != RIGHTS_LEN as u64
                || rights[1] != (libc::SOL_SOCKET as u64 | ((libc::SCM_RIGHTS as u64) << 32))
                || (rights[2] as i32) < 0
            {
                return Err(anyhow::anyhow!("invalid native SCM_RIGHTS response").into());
            }
            let fd = rights[2] as i32;
            *imported_slot = Some(fd);
            *unknown_import = false;
            // The syscall must use this exact OFD, not merely the same inode.
            // Verify custody after SCM_RIGHTS installation, before any effect.
            let same = unsafe {
                libc::syscall(
                    libc::SYS_kcmp,
                    task.tid.as_raw(),
                    libc::getpid(),
                    0,
                    fd as libc::c_ulong,
                    backing.as_raw_fd() as libc::c_ulong,
                )
            };
            if same != 0 {
                return Err(anyhow::anyhow!("imported native descriptor custody unproved").into());
            }
            let (nr, args) = match operation {
                ImportedOperation::Map {
                    address,
                    length,
                    prot,
                    flags,
                } => (
                    Sysno::mmap,
                    SyscallArgs::new(
                        address.unwrap_or(0) as usize,
                        length,
                        prot as usize,
                        flags as usize,
                        fd as usize,
                        0,
                    ),
                ),
                ImportedOperation::Flock(operation) => (
                    Sysno::flock,
                    SyscallArgs::new(fd as usize, operation as usize, 0, 0, 0, 0),
                ),
            };
            Ok(task.inject_descriptor_call(nr, args).await)
        }
        .await;
        // No guest instruction executes while temporary descriptors exist.
        // VMAs or the supervisor pin retain the actual OFD after these closes.
        // An interrupted transport instead invokes whole-tree cleanup: its file
        // table may still be shared by another live guest thread.
        for fd in imported.into_iter().chain(pair) {
            self.inject_descriptor_call(
                Sysno::close,
                SyscallArgs::new(fd as usize, 0, 0, 0, 0, 0),
            )
            .await
            .map_err(|error| {
                anyhow::anyhow!("cannot close native transport descriptor: {error}")
            })?;
        }
        // If recvmsg installed a right but copyout/validation could not recover
        // its number, closing the socketpair is insufficient. Keep the guard
        // armed so even a Tool that catches this error cannot resume the guest.
        transport.armed = imported_descriptor_unknown;
        result
    }
}
