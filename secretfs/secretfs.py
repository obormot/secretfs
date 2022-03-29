#!/usr/bin/env python3
"""
SecretFS is a security focused FUSE filesystem providing fine-grained
access control to application secrets in a hardened Linux, MacOS, and FreeBSD.

Requirements:
- FUSE
- pip install psutil fusepy

Author: Oscar Ibatullin
"""
from argparse import ArgumentParser
from configparser import ConfigParser
from errno import EACCES
from math import ceil
from time import time
import grp
import logging
import os
import pwd
import stat
import sys

from fuse import FUSE, FuseOSError, LoggingMixIn, Operations, fuse_get_context
import psutil

# constants
CONF_FILE = '/etc/secretfs.conf'  # ACL configuration file
LOG_FILE = '/var/log/secretfs.log'

# globals
ACLS = []


# decorator to check access
def restricted(func):
    def wrapped(self, path, *args, **kwargs):
        uid, gid, pid = fuse_get_context()
        username = pwd.getpwuid(uid).pw_name
        groupname = grp.getgrgid(gid).gr_name
        try:
            pr = psutil.Process(pid)
        except psutil.NoSuchProcess:
            raise FuseOSError(EACCES)

        # strip the leading fuse root
        path = path.lstrip('/')

        # get process attributes
        pr_attrs = pr.as_dict(attrs=['exe', 'cmdline', 'create_time'])

        process = pr_attrs['exe']

        # strip the 1st arg in the cmdline; could be a relative or abs path to the exe
        cmdline = ' '.join(pr_attrs['cmdline'][1:])

        # process runtime
        runtime = ceil(time() - pr_attrs['create_time'])

        # log the access request
        logging.info(f"access request | path [{path}], func [{func.__name__}], "
                     f"user [{username} ({uid})], group [{groupname} ({gid})], "
                     f"exe [{process}], cmd [{cmdline}], runtime [{runtime}s]")

        acl_match = False
        for acl in ACLS:
            # required fields
            if path != acl['path']:
                continue

            if process != acl['process']:
                continue

            if cmdline != acl['cmdline']:
                continue

            # optional fields
            user = acl['user']
            if user == '*':  # allow any user
                pass
            elif isinstance(user, int):
                if uid != user:
                    continue
            elif username != user:
                continue

            group = acl['group']
            if group == '*':  # allow any group
                pass
            elif isinstance(group, int):
                if gid != int(group):
                    continue
            elif groupname != group:
                continue

            if acl['ttl'] == 0:  # no time limit
                pass
            elif runtime > acl['ttl']:
                logging.info('access denied: exceeded ttl')
                raise FuseOSError(EACCES)

            acl_match = True
            logging.info(f'access granted, rule: {acl["rule_id"]}')
            break

        if not acl_match:
            logging.info('access denied: no matching acl')
            raise FuseOSError(EACCES)

        return func(self, path, *args, **kwargs)
    return wrapped


class SecretFS(LoggingMixIn, Operations):
    def __init__(self, root, disable_ls):
        self.root = root
        self.disable_ls = disable_ls

    def _full_path(self, path):
        return os.path.join(self.root, path.lstrip('/'))

    # Filesystem methods
    # ==================

    def access(self, path, mode):
        path = self._full_path(path)
        if not os.access(path, mode):
            raise FuseOSError(EACCES)

    def getattr(self, path, fh=None):
        path = self._full_path(path)
        st = os.lstat(path)
        return {a: getattr(st, a) for a in dir(st) if a.startswith('st_')}

    def statfs(self, path):
        path = self._full_path(path)
        st = os.statvfs(path)
        return {a: getattr(st, a) for a in dir(st) if a.startswith('f_')}

    def readdir(self, path, fh=None):
        if self.disable_ls:
            logging.debug('directory listing is disabled')
            raise FuseOSError(EACCES)

        path = self._full_path(path)
        if os.path.isdir(path):
            yield '.'
            yield '..'
            for r in os.listdir(path):
                yield r

    # File methods
    # ============

    @restricted
    def open(self, path, flags):
        path = self._full_path(path)
        return os.open(path, flags)

    @restricted
    def read(self, path, length, offset, fh):
        os.lseek(fh, offset, os.SEEK_SET)
        return os.read(fh, length)

    def release(self, path, fh):
        return os.close(fh)


# helper functions

def load_configuration():
    """Load the configuration file"""

    # check the config file ownership and permissions
    # max acceptable are -rw-r-r-- root
    try:
        fstat = os.stat(CONF_FILE)
    except (FileNotFoundError, OSError):
        sys.exit(f"could not find the config file [{CONF_FILE}], exiting")

    if fstat.st_uid != 0:
        sys.exit(f"config file [{CONF_FILE}] is not owned by root (uid=0), exiting")

    # check file permission mask
    # 0o022 = mask for group-write|other-write; allow owner-write only
    if fstat.st_mode & 0o666 & 0o022:
        sys.exit(f"config file [{CONF_FILE}] has excessive permissions, exiting")

    conf = ConfigParser()
    try:
        with open(CONF_FILE, 'r') as fh:
            conf.read_file(fh)
    except OSError:
        sys.exit(f"could not load the config file [{CONF_FILE}], exiting")
    return conf


def load_acl_rules(conf, fuse_root):
    """Load ACLs from the configuration file"""
    global ACLS

    def dequote(s):
        """remove single or double quotation around the string"""
        if s and s[0] == s[-1] and s.startswith(("'", '"')):
            return s[1:-1]
        return s

    def int_or_str(v):
        try:
            return int(v)
        except ValueError:
            return v

    # ensure that the files containing secrets are owned by root and not world-readable
    for secname, section in conf.items():
        if secname == 'DEFAULT':
            continue

        path = dequote(section['path']).lstrip('/')
        filepath = os.path.join(fuse_root, path)
        try:
            fstat = os.stat(filepath)
        except (FileNotFoundError, OSError):
            logging.warning(f"secrets file [{filepath}] could not be opened, skipping")
            continue  # warn and continue

        if fstat.st_uid != 0:
            sys.exit(f"secrets file [{filepath}] is not owned by root (uid=0), exiting")

        # check file permission mask
        if fstat.st_mode & 0o666 & 0o022:
            sys.exit(f"secrets file [{filepath}] has excessive permissions, exiting")

        # all good - pre-process add the ACL
        ACLS.append({
            'rule_id': secname,
            'path': path,
            'process': dequote(section['process']),
            'cmdline': dequote(section.get('cmdline', fallback='')),
            'user': int_or_str(dequote(section['user'])),
            'group': int_or_str(dequote(section['group'])),
            'ttl': section.getint('ttl', fallback=0),
        })

    if not ACLS:
        sys.exit("no ACL rules found in the config, exiting")

    logging.debug(f"loaded {len(ACLS)} acl rules")


# mount.fuse passes 2 positional arguments:
# <dev>(mountpoint) <path>(fuse root)

def main():
    ap = ArgumentParser()
    ap.add_argument('MOUNTDIR', help='mount point')
    ap.add_argument('SOURCEDIR', help='source directory containing secrets')
    ap.add_argument('--verbose', action='store_true', help='enable verbose logging')
    ap.add_argument('--foreground', action='store_true', help='run in foreground and log to stdout')
    ap.add_argument('--disable-ls', action='store_true', help='disable directory listing for extra security')
    ap.add_argument('-o', dest='options', default='', help='mount options placeholder (ignored)')
    args = ap.parse_args()

    # --flags will be passed via -o in fstab
    opts = [opt.strip() for opt in args.options.split(',')]
    if '--disable-ls' in opts:
        args.disable_ls = True
    if '--verbose' in opts:
        args.verbose = True

    # configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    log_kwargs = {} if args.foreground else {'filename': LOG_FILE}
    logging.basicConfig(level=log_level, format="%(asctime)s %(message)s", **log_kwargs)

    conf = load_configuration()
    load_acl_rules(conf, args.SOURCEDIR)

    logging.info(f"Starting up SecretFS, mount point: {args.MOUNTDIR}, secrets root: {args.SOURCEDIR}")
    logging.debug(f"args: {vars(args)}, opts: {opts}")

    # create the mountpoint if needed
    try:
        os.mkdir(args.MOUNTDIR)
    except OSError:
        pass

    FUSE(
        SecretFS(args.SOURCEDIR, args.disable_ls),
        args.MOUNTDIR,
        nothreads=True,   # run single-threaded to prevent race conditions
        foreground=args.foreground,
        allow_other=True,  # allow other(=all) users to access the file system
        ro=True,  # read-only filesystem
        nodev=True, nosuid=True, noexec=True,
    )
    logging.info("Shutting down SecretFS")


if __name__ == '__main__':
    main()
