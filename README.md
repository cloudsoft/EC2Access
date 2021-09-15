Convenient and secure access to Windows EC2 Instances with Remote Desktop (RDP)
===============================================================================

Getting remote access to Windows-based EC2 instances has always been trickier than the equivalent for Linux
instances. Whereas with a Linux instance it is a single command to get a fully-functional shell, to get access
to the desktop of a Windows instance you need to:

1. Use the EC2 console to request the Administrator password
2. Start the Remote Desktop client and give it the EC2 instance address
3. Provide the Administrator credentials

It's several more steps and each step involves several clicks or clipboard operations.

This module aims to reduce this down to a single step, allowing a single command to start a Remote Desktop
session with no need for completing dialog boxes or manually supplying credentials. It works by automating all
of the above steps:

1. The encrypted blob containing the Administrator password is fetched and then decrypted locally.
2. The Administrator credentials are pre-loaded into the Remote Desktop client's credential store, so there is
   no need to manually enter them when making the connection.
3. The Remote Desktop client is started using the hostname for the EC2 instance.

Furthermore, Systems Manager Session Manager's port forwarding functionality is fully integrated. If an EC2
instance is configured for Session Manager, then this module can connect using a Session Manager forwarded
port, even if the instance is not reachable on a public IP address.


Prerequisites
-------------

Firstly, you will need to install the AWS Tools for PowerShell. There are a few ways of installing
this, which are described in the AWS documentation page
[Installing the AWS Tools for PowerShell on Windows](https://docs.aws.amazon.com/powershell/latest/userguide/pstools-getting-set-up-windows.html).
We recommend installing the AWS Tools installer from the PowerShell Gallery and then installing the
EC2 and SimpleSystemsManagement module. Usually, this can be done with these commands:

```powershell
Install-Module -Name AWS.Tools.Installer
Install-AWSToolsModule EC2,SimpleSystemsManagement
```

If you would also like to use the Session Manager integration (which is recommended, as you can
keep the RDP port off the public Internet), then you also need to 
[Install the Session Manager plugin on Windows](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html#install-plugin-windows)
as described in the AWS documentation.


Installation
------------

The module must be installed somewhere in the `$env:PSModulePath`. Usually, the
`Documents\WindowsPowerShell\Modules` directory will do this job, but check the module path with
a command like this to make sure:

```powershell
( Get-Item Env:\PSModulePath ).Value.Split(";")
```

Once you have identified a suitable modules directory, create a folder called `EC2Access`, and fill
it with the files from this repository.

Then verify that the installation was successful with these commands:

```powershell
Import-Module EC2Access
help Start-DirectEC2RemoteDesktop
```

If installation was successful, you will see the documentation for the Start-DirectEC2RemoteDesktop
command.


Usage
-----

### About private keys

To be able to decrypt the Administrator password, you will need the private key. Typically, there are two ways
to get a private key.

1. Creating a keypair on the EC2 *Key pairs* page. EC2 will generate a private+public key pair and store the
   public key. The private key is downloaded to your workstation as a file with a `.pem` extension - it is
   then discarded by AWS so make sure that you keep the downloaded private key file.
2. Creating a keypair on your workstation. This is usually done using with the `ssh-keygen` tool that comes
   with Git for Windows or the Windows native OpenSSH tools if you have installed them. By default this
   creates the private key in `.ssh\.id_rsa` in your home directory, and corresponding public key with the
   same name with a `.pub` extension. Then, using the *Import* button on the EC2 *Key pairs* page to import
   the public key.

By default, the functions in this module will assume that your private key is in the ".ssh\id_rsa" file in
your home directory, which will be the normal situation in method 2 above. If you have used method 1, or have
your key in any other location, simply pass a "-PrivateKeyFile" parameter to the functions with the path to
your private key file.


### Examples

If your EC2 instance is configured for Systems Manager Session Manager, and if you have installed the AWS
Session Manager plugin tool, then you can start a Remote Desktop session with this command:

```powershell
Start-EC2RemoteDesktopViaSessionManager i-12345678abcd
```

This assumes your instance is in the default region, as specified in environment variables or your AWS client
configuration files. You can specify the region explicitly:

```powershell
Start-EC2RemoteDesktopViaSessionManager -InstanceId i-12345678abcd -Region eu-west-2
```

You can specify the location of the private key file:

```powershell
Start-EC2RemoteDesktopViaSessionManager -InstanceId i-12345678abcd `
                                        -PrivateKeyFile C:\Users\joe\Downloads\windows.pem
```

If your EC2 instance is reachable on its public IP address, then instead of
"Start-EC2RemoteDesktopViaSessionManager", you can invoke "Start-DirectEC2RemoteDesktop". This function takes
exactly the same parameters but uses the public IP address instead of Session Manager port forwarding.

```powershell
Start-DirectEC2RemoteDesktop -InstanceId i-12345678abcd -Region eu-west-2
```


License
-------

The original content in this project is provided under this license:

    Copyright 2021 Cloudsoft Corporation Ltd

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

See [LICENSE](LICENSE) for the full license text.

This project incorporations portions of the Bouncy Castle project. Refer to
[LICENSE-BouncyCastle](LICENSE-BouncyCastle) for more information.
