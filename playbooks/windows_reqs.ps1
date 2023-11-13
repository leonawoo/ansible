<powershell>
# Install the OpenSSH Client
Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0

# Install the OpenSSH Server
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

# Start the SSH service
Start-Service sshd

# Set SSH service to start automatically
Set-Service -Name sshd -StartupType 'Automatic'

# Confirm the Firewall rule is configured. It should be created automatically by setup. Run the following to verify
if (!(Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue | Select-Object Name, Enabled)) {
    Write-Output "Firewall Rule 'OpenSSH-Server-In-TCP' does not exist, creating it..."
    New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
} else {
    Write-Output "Firewall rule 'OpenSSH-Server-In-TCP' has been created and exists."
}

# Configure the ssh-agent service to start automatically
Get-Service ssh-agent | Set-Service -StartupType Automatic

# Start the ssh-agent service
Start-Service ssh-agent

# Check the status of ssh-agent service
Get-Service ssh-agent

# Define the path to the .ssh directory
$sshDirectory = "C:\Users\Administrator\.ssh"

# Check if the .ssh directory exists, if not, create it
if (-not (Test-Path -Path $sshDirectory)) {
    New-Item -ItemType Directory -Path $sshDirectory -Force
}

# Define the path to the authorized_keys file
$authorizedKeysPath = Join-Path -Path $sshDirectory -ChildPath "authorized_keys"

# Define the public key
$publicKey = "ssh-rsa <<PUBLIC_KEY_HERE>>"

# Write the public key to the authorized_keys file
Set-Content -Path $authorizedKeysPath -Value $publicKey

# Set the correct permissions for the authorized_keys file
icacls $authorizedKeysPath /inheritance:r /grant "Administrators:F" /grant "SYSTEM:F"


# Add a public key to the administrators_authorized_keys file
$content = @"
-----BEGIN PUBLIC KEY-----
ADD PUBLIC KEY
-----END PUBLIC KEY-----
"@

# Set the public key content to the administrators_authorized_keys file
Set-Content -Path 'C:\ProgramData\ssh\administrators_authorized_keys' -Value $content

# Set the correct ACL for the administrators_authorized_keys file
icacls.exe "C:\ProgramData\ssh\administrators_authorized_keys" /inheritance:r /grant "Administrators:F" /grant "SYSTEM:F"

# Update the sshd_config file for public key authentication
$configPath = "$env:ProgramData\ssh\sshd_config"
$config = Get-Content -Path $configPath

# Uncomment 'PubkeyAuthentication yes' and set 'PasswordAuthentication no'
$config = $config -replace '#PubkeyAuthentication yes', 'PubkeyAuthentication yes'
$config = $config -replace 'PasswordAuthentication yes', 'PasswordAuthentication no'

# Comment out 'Match Group administrators' and the following 'AuthorizedKeysFile' line
$config = $config -replace 'Match Group administrators', '#Match Group administrators'
$config = $config -replace 'AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys', '#AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys'

# Write the updated configuration back to the file
Set-Content -Path $configPath -Value $config

# Restart the sshd service to apply changes
Restart-Service sshd

</powershell>