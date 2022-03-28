SecretFS
========

SecretFS is a security focused FUSE-based filesystem providing fine-grained access controls to application secrets in a hardened Linux, MacOS, and FreeBSD.


Use cases
---------

Let's say you're building an old-school IoT device with a bunch of services and would like to harden its Linux so that if the system is compromised, an attacker (operating as a non-root user) won't be able to freely access secrets laying around on the filesystem. You could approach this by creating dedicated users and groups; e.g. only mysql user would have access to the password file for MySQL and no one else. However, in some cases this approach is not feasible, or not granular or secure enough. When multiple processes need access to various secrets, group-based privilege separation may quickly turn into a dependency hell.

Another use case is AppArmor and interpreted languages. You may have a bunch of Python scripts running as "python foo.py", or "python bar.py". It's challenging to write an AppArmor profile for the python executable that'll restrict foo.py from accessing secrets intended only for bar.py. You could solve this by creating virtual environments and multiple copies of Python, but that's just not so DRY, isn’t it?

For another use case, you'd like to follow some great recommendations given in [this blog post](http://https://blog.forcesunseen.com/stop-storing-secrets-in-environment-variables "this blog post") and store the your app secrets on ephemeral mounts allowing access only at the apps' initialization, so in case the app is compromised later during its runtime the attacker won't be able to fetch the secrets.


### Enter SecretFS

SecretFS enables you to achieve this granularity with a single easy configuration, transparency and no app code changes, by making your secrets accessible on a read-only and ACL-controlled FUSE volume. It goes like this:
1. Store all your application secrets as files accessible only by root, structured under a single parent directory (aka the “secrets store”).
2. Define the ACL (access control list) for your secrets, restricting access to specific binaries, running with a specific command line, as a specific user and/or group, and optionally limit the time the secrets can be read within.
3. Mount the SecretFS volume, where applications will be reading their secrets from.


Installation
------------

1. `sudo pip install secretfs`
2. find the installed `etc/secretfs.conf-example` file in the Python modules directory on your system, edit to create your ACLs, and copy it over into `/etc/secretfs.conf`

#### Prerequisites

- Python3
- FUSE
    Ubuntu
        sudo apt-get install fuse

    OSX Homebrew
        brew install macfuse


Creating ACLs
-------------

ACLs are defined in `/etc/secretfs.conf` as follows:

```
# SecretFS configuration file
# /etc/secretfs.conf

# ACLs

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

1. from the command line:

        $ sudo secretfs <mountpoint> <directory containing secrets>
    e.g.
        $ sudo secretfs /mnt/secrets /opt/secrets-store/

   or more expicitly, using Python:

        $ sudo python3 /path/to/secretfs.py /mnt/secrets /opt/secrets-store/

2. with the `mount.fuse` command:

        $ sudo mount.fuse secretfs#/mnt/secrets /opt/secrets-store/

   or more expicitly:

        $ sudo mount.fuse /path/to/secretfs.py#/mnt/secrets /opt/secrets-store/

   debugging:

        sudo python3 secretfs.py --verbose --foreground /mnt/secrets /opt/secrets-store/

3. fstab entry

        secretfs#/mnt/secrets /opt/secrets-store/ fuse auto 0 0

   or more expicitly:

        /path/to/secretfs.py#/mnt/secrets /opt/secrets-store/ fuse auto 0 0

   specifying command line options in fstab:

        secretfs#/mnt/secrets /opt/secrets-store/ fuse --disable-ls,--verbose 0 0

   then run `sudo mount -a` to mount, `umount /mnt/secrets` to unmount


Gotchas
-------

Note that catching the process path can be non-intuitive. Even though you may be starting your application with `/usr/bin/python`, it may unwind into something like `"/usr/local/Cellar/python@2/2.7.17_1/Frameworks/Python.framework/Versions/2.7/Resources/Python.app/Contents/MacOS/Python"` in the secretfs access log, which is what must be used in the ACL entry. That's why reviewing the log is the recommended way to go about creating the ACLs.

Same applies to the command line (`cmdline` in the ACL rule). SecretFS will distinguish between `cat secret.txt` and `cat ./secret.txt`.

When running in the terminal,` secretfs.py` would normally terminate on Ctrl-C (or Command+C), and unmount its volume, unless the resource is busy (e.g. there's an active bash shell with `cd /mnt/secrets`). In this case FUSE will silently ignore the termination request. Just cd out of the mount point and it'll unmount fine.
