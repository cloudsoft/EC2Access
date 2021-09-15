#
# Main code and public interface for EC2Access module
#
#
# Copyright 2021 Cloudsoft Corporation Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

$ErrorActionPreference = 'Stop'

function Convert-RSAEncryptedCipherTextToClearText {
  Param (
      [Parameter(Mandatory=$true)][Alias('pem')][Alias('p')][string]$pemFile,
      [Parameter(Mandatory=$true)][Alias('cipher')][string]$cipherText
    )
  
  if (-not (Test-Path -Path $pemFile)) {
    # file does not exist - handle error
  }

  $sr = [System.IO.StreamReader]::new($pemFile)
  $pr = [Org.BouncyCastle.OpenSsl.PemReader]::new($sr)
  $keyPair = $pr.ReadObject()
  $rsa = [Org.BouncyCastle.Security.DotNetUtilities]::ToRSA($keyPair.Private)
  $cipherBytes = [System.Convert]::FromBase64String($cipherText)
  $clearBytes = $rsa.Decrypt($cipherBytes, $false)

  Return [System.Text.Encoding]::ASCII.GetString($clearBytes)
}

<#
  .SYNOPSIS
  Get the Administrator password for a Windows EC2 instance.

  .PARAMETER InstanceId
  The AWS EC2 instance ID. This is the string "i-" followed by a series of hexadecimal digits.

  .PARAMETER Region
  The AWS region containing the instance. If omitted, the region is fetched from the environment or the AWS configuration files.

  .PARAMETER PrivateKeyFile
  A file containing the private key to decrypt the password. This must be in "PEM" format, as used by SSH and as given by AWS if you use it to create a keypair. If omitted, it will default to ".ssh\id_rsa" from your home directory.

  .DESCRIPTION
  This function queries the AWS APIs for the encrypted password data of an EC2 instance, and then attempts to decrypt it using a private key stored in a file on your computer. The decrypted password is returned as a SecureString.

  AWS EC2 contains a public key store. When starting an EC2 instance, you will be required to choose a public key. For Windows instances, EC2 will generate a random password, assign it to the Administrator user, and then encrypt the password using the chosen public key and stores it in the EC2 control plane.

  This function will fetch the encrypted data, then decrypt it using the private key. The private key must be in a file on disk and written in PEM format. This is the standard format using by SSH for storing private keys. If you use EC2's "Create key" function, it will store the public key and then download the private key in PEM format to you (without storing it).

  .EXAMPLE
  Get-EC2Password -InstanceId i-12345678abcd -Region eu-west-2

  .OUTPUTS
  A SecureString object containing the password for the EC2 instance.
#>
function Get-EC2Password {
  [CmdletBinding()] param(
    [Parameter(Mandatory=$true, Position=0)] [string]$InstanceId,
    [Parameter(Position=1)] [string]$Region,
    [Parameter(Position=2)] [string]$PrivateKeyFile
  )

  $ErrorActionPreference = "Stop"

  # Verify the private key files exists
  if($null -eq $PrivateKeyFile) {
    $PrivateKeyFile = $HOME + '\.ssh\id_rsa'
  }
  if(-not (Test-Path $PrivateKeyFile)) {
    Write-Error "$($PrivateKeyFile) does not exist. Do you need to use -PrivateKeyFile argument?"
  }

  Write-Verbose "Requesting password data from AWS"
  $cipherText = (Get-EC2PasswordData -Region $Region -InstanceId $InstanceId)

  Write-Verbose "Decrypting password"
  $password = Convert-RSAEncryptedCipherTextToClearText -PemFile $PrivateKeyFile -CipherText $cipherText

  return (ConvertTo-SecureString -String $password -AsPlainText -Force)
}

<#
  .SYNOPSIS
  Start a Remote Desktop session with a Windows EC2 instance on a public IP address.

  .PARAMETER InstanceId
  The AWS EC2 instance ID. This is the string "i-" followed by a series of hexadecimal digits.

  .PARAMETER Region
  The AWS region containing the instance. If omitted, the region is fetched from the environment or the AWS configuration files.

  .PARAMETER PrivateKeyFile
  A file containing the private key to decrypt the password. This must be in "PEM" format, as used by SSH and as given by AWS if you use it to create a keypair. If omitted, it will default to ".ssh\id_rsa" from your home directory.

  .DESCRIPTION
  Start a Remote Desktop session with an EC2 instance. The instance must have a public IP address and a security group rule that permits access from your public IP address.

  This function will retrieve the Windows Administrator password (see Get-EC2Password) and "pre-load" the credentials into the Remote Desktop client, so that you will not need to manually enter credentials into the Remote Desktop client.

  If your instance is not reachable by public IP address, but it is configured for Systems Manager Session Manager, see Start-EC2RemoteDesktopViaSessionManager for a way to start Remote Desktop sessions.

  .EXAMPLE
  Start-DirectEC2RemoteDesktop -InstanceId i-12345678abcd -Region eu-west-2
#>
function Start-DirectEC2RemoteDesktop {
  [CmdletBinding(SupportsShouldProcess)] param(
    [Parameter(Mandatory=$true, Position=0)] [string]$InstanceId,
    [Parameter(Position=1)] [string]$Region,
    [Parameter(Position=2)] [string]$PrivateKeyFile
  )
  
  $password = Get-EC2Password -Instance $InstanceId -Region $Region -PrivateKeyFile $PrivateKeyFile
  $Credential = New-Object PSCredential "Administrator",$password

  $instance = (Get-EC2Instance -Region $Region -InstanceId $InstanceId).Instances[0]
  $HostName = $instance.PublicIpAddress
  Write-Verbose "Instance IP address is $HostName"

  if ($PSCmdlet.ShouldProcess($InstanceId,'Start remote desktop session')) {
    Start-RemoteDesktop -HostName $HostName -Credential $Credential
  }
}

<#
  .SYNOPSIS
  Start a Remote Desktop session with a Windows EC2 instance using Systems Manager Session Manager.

  .PARAMETER InstanceId
  The AWS EC2 instance ID. This is the string "i-" followed by a series of hexadecimal digits.

  .PARAMETER Region
  The AWS region containing the instance. If omitted, the region is fetched from the environment or the AWS configuration files.

  .PARAMETER PrivateKeyFile
  A file containing the private key to decrypt the password. This must be in "PEM" format, as used by SSH and as given by AWS if you use it to create a keypair. If omitted, it will default to ".ssh\id_rsa" from your home directory.

  .DESCRIPTION
  Start a Remote Desktop session with an EC2 instance. The instance must be configured to support Systems Manager Session Manager. This function will configure a Session Manager port forwarding session and invoke the Remote Desktop client through the forwarded port.

  This function will retrieve the Windows Administrator password (see Get-EC2Password) and "pre-load" the credentials into the Remote Desktop client, so that you will not need to manually enter credentials into the Remote Desktop client.

  .EXAMPLE
  Start-EC2RemoteDesktopViaSessionManager -InstanceId i-12345678abcd -Region eu-west-2
#>
function Start-EC2RemoteDesktopViaSessionManager {
  [CmdletBinding(SupportsShouldProcess)] param(
    [Parameter(Mandatory=$true, Position=0)] [string]$InstanceId,
    [Parameter(Position=1)] [string]$Region,
    [Parameter(Position=2)] [string]$PrivateKeyFile
  )
  
  $password = Get-EC2Password -Instance $InstanceId -Region $Region -PrivateKeyFile $PrivateKeyFile
  $Credential = New-Object PSCredential "Administrator",$password

  $LocalPort = 33389
  $PortForwardParams = @{ portNumber=(,"3389"); localPortNumber=(,$LocalPort.ToString()) }
  $session = Start-SSMSession -Target $InstanceId -Region $Region -DocumentName AWS-StartPortForwardingSession -Parameters $PortForwardParams

  # We now need to emulate awscli - it invokes session-manager-plugin with the new session information.
  # AWS Tools for PowerShell don't do this. Also some of the objects seem to look a bit different, and the
  # plugin is pernickety, so we have to jump through some hoops to get all the objects matching up as close
  # as we can.

  $SessionData = @{
    SessionId=$session.SessionID;
    StreamUrl=$session.StreamUrl;
    TokenValue=$session.TokenValue;
    ResponseMetadata=@{
      RequestId=$session.ResponseMetadata.RequestId;
      HTTPStatusCode=$session.HttpStatusCode;
      RetryAttempts=0;
      HTTPHeaders=@{
        server="server";
        "content-type"="application/x-amz-json-1.1";
        "content-length"=$session.ContentLength;
        connection="keep-alive";
        "x-amzn-requestid"=$session.ResponseMetadata.RequestId;
      }
    }
  }

  $RequestData = @{
    Target=$InstanceId;
    DocumentName="AWS-StartPortForwardingSession";
    Parameters=$PortForwardParams
  }

  $Arguments = (
    (ConvertTo-Json $SessionData -Compress),
    $Region,
    "StartSession",
    "",
    (ConvertTo-Json $RequestData -Compress),
    "https://ssm.$($Region).amazonaws.com"
  )

  # Now we have to do some PowerShell hacking. Start-Process takes an array of arguments, which is great,
  # but it doesn't actually do what we expect it to - see https://github.com/PowerShell/PowerShell/issues/5576.
  # So instead we have to turn it into an escaped string ourselves...
  $EscapedArguments = $Arguments | ForEach-Object { $escaped = $_ -replace "`"", "\`""; "`"$($escaped)`"" }
  $ArgumentString = $EscapedArguments -join " "

  # Start the Session Manager plugin:
  if ($PSCmdlet.ShouldProcess($session.SessionId,'Start Session Manager plugin')) {
    try {
      $Process = Start-Process -FilePath "session-manager-plugin.exe" -ArgumentList $ArgumentString -NoNewWindow -PassThru
    } catch {
      Write-Error "Unable to start the process session-manager-plugin.exe. Have you installed the Session Manager Plugin as described in https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html#install-plugin-windows ?"
      exit
    }
    # Wait a moment for it to connect to the session and open up the local ports
    Start-Sleep -Seconds 1

    # The port should be open now - let's connect
    if ($PSCmdlet.ShouldProcess($InstanceId,'Start remote desktop session')) {
      Start-RemoteDesktop -HostName "127.0.0.1" -Credential $Credential -Port $LocalPort
    }

    # Once the desktop session has finished, kill the session manager plugin
    $Process.Kill()
  }

}

function Start-RemoteDesktop {
  [CmdletBinding(SupportsShouldProcess)] param(
    [Parameter(Mandatory=$true, Position=0)] [String] [string]$HostName,
    [Parameter(Mandatory=$true, Position=1)] [PSCredential] [string]$Credential,
    [Parameter()] [Int32] [string]$Port
  )

  $nwcredential = $Credential.GetNetworkCredential()

  if ($PSCmdlet.ShouldProcess($HostName,'Adding credentials to store')) {
    Start-Process -FilePath "$($env:SystemRoot)\system32\cmdkey.exe" -ArgumentList ("/generic:TERMSRV/$HostName","/user:$($nwcredential.UserName)","/pass:$($nwcredential.Password)") -WindowStyle Hidden -Wait
  }

  if ($PSCmdlet.ShouldProcess($HostName,'Connecting mstsc')) {
    if ($PSBoundParameters.ContainsKey('Port')) {
      $target = "$($HostName):$($Port)"
    } else {
      $target = $HostName
    }
    Start-Process -FilePath "$($env:SystemRoot)\system32\mstsc.exe" -ArgumentList ("/v",$target) -NoNewWindow -Wait
  }
}

Export-ModuleMember -Function Get-EC2Password
Export-ModuleMember -Function Start-EC2RemoteDesktopViaSessionManager
Export-ModuleMember -Function Start-DirectEC2RemoteDesktop
