
SecretFS is a security focused FUSE filesystem providing fine-grained access control to application secrets in a hardened Linux, MacOS, and FreeBSD. It mirrors an existing directory tree into a read-only FUSE volume and grants or denies applications' access to files based on the user-defined ACLs (access control lists). The logic of protecting the secrets is handled by the filesystem itself with no code changes to the application.

SecretFS ACLs can restrict access to a specific process, running with a specific command line, as a specific user and/or group, and optionally within a defined time limit. It enables security practices highlighted in [this blog post](http://https://blog.forcesunseen.com/stop-storing-secrets-in-environment-variables "this blog post"), which recommends storing your app secrets on ephemeral mounts allowing access only at the apps' initialization, so in case the app is compromised later during its runtime the attacker won't be able to fetch the secrets.


Installation
------------

1. `sudo pip install secretfs` (or install without sudo and symlink `secretfs` script into the root's $PATH)
2. find the installed `etc/secretfs.conf-example` file, edit to create your ACLs and save as `/etc/secretfs.conf`

### Prerequisites

- Python3
- FUSE

    Ubuntu: `sudo apt-get install fuse`

    OSX Homebrew: `brew install macfuse`


### Creating ACLs

ACLs are defined in `/etc/secretfs.conf` as follows:

```
# [rule_id] - any id or name of the ACL rule; must be unique
#   path    - path to the the secret, relative to the root directory specified at mount time
#   process - full path to the process requesting access
#   cmdline - full command line following the process executable;
#              empty string or no value means empty command line
#   user    - uid or name of the user to grant access to;
#              '*' means any user is allowed
#   group   - gid or name of the group to grant access to
#              '*' means any group is allowed
#   ttl     - time since the process creation during which access will be granted, in seconds;
#              0 or no value means don't enforce the time limit

[app-foo-secret1-rule1]
path = secret1.txt
process = /usr/bin/foo
cmdline = secret1.txt
user = ubuntu
group = *
;ttl = 0        -- no time limit

[app-foo-secret2.pem]
path = subdir/secret2.txt
...

```

All attempts to access files on the secretfs volume are logged into `/var/log/secretfs.log` (or to stdout if running with `--foreground`).
After mounting the SecretFS volume try accessing the secrets from your application; then find the corresponding entry in the log and create the ACL entry using the captured information. Restart SecretFS and try accessing it again to verify the new ACL rule results in a match, and access is granted as intended.


Mounting
--------

As with any FUSE-based filesystem, there are several ways to mount SecretFS

1. From the command line:

        $ sudo secretfs <mountpoint> <directory containing secrets>
    e.g.

        $ sudo secretfs /mnt/secrets /opt/secrets-store/

   or more expicitly, using Python:

        $ sudo python3 /path/to/secretfs.py /mnt/secrets /opt/secrets-store/

2. With `mount.fuse` command:

        $ sudo mount.fuse secretfs#/mnt/secrets /opt/secrets-store/

   or more expicitly:

        $ sudo mount.fuse /path/to/secretfs.py#/mnt/secrets /opt/secrets-store/

   Debugging:

        sudo python3 secretfs.py --verbose --foreground /mnt/secrets /opt/secrets-store/

3. `/etc/fstab` entry

        secretfs#/mnt/secrets /opt/secrets-store/ fuse auto 0 0

   or more expicitly:

        /path/to/secretfs.py#/mnt/secrets /opt/secrets-store/ fuse auto 0 0

   Specifying command line options in fstab:

        secretfs#/mnt/secrets /opt/secrets-store/ fuse --disable-ls,--verbose 0 0

   then run `sudo mount -a` to mount, `umount /mnt/secrets` to unmount


Gotchas
-------

Note that catching the process path for the ACL can be non-intuitive. One may be starting their application with `/usr/bin/python`, but it unwinds into something like `"/usr/local/Cellar/python@2/2.7.17_1/Frameworks/Python.framework/Versions/2.7/Resources/Python.app/Contents/MacOS/Python"` in the secretfs access log. That's why reviewing the log is the recommended way to creating ACLs.

Same strictness applies to the command line (`cmdline` in the ACL rule). SecretFS will distinguish between `cat secret.txt` and `cat ./secret.txt`.

When running in the terminal, `secretfs.py` would normally terminate on Ctrl-C (or Command+C), and unmount its volume, unless the resource is busy (e.g. there's an active bash shell with `cd /mnt/secrets`). In this case FUSE will silently ignore the termination request. Just cd out of the mount point directory and it should unmount fine.


DISCLAIMER
----------

SecretFS is an experimental project and has not been evaluated by independent security experts. Use at your own risk.
root has full access to all secrets and can't be restricted by SecretFS. Has not been tested on FreeBSD.
