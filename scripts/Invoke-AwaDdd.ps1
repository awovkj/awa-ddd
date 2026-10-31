param(
    [Parameter(Mandatory = $true)][string]$RequestFile,
    [string]$OutputFile,
    [string]$Workspace,
    [ValidateSet('native', 'wsl')][string]$Backend = 'native',
    [string]$Distribution = 'kali-linux',
    [string]$PythonExecutable,
    [string]$WslPythonExecutable,
    [int]$TimeoutMs = 120000
)

$ErrorActionPreference = 'Stop'
$utf8 = New-Object System.Text.UTF8Encoding($false)
$previousInput = [Console]::InputEncoding
$previousOutput = [Console]::OutputEncoding
$previousPipe = $OutputEncoding
try {
    [Console]::InputEncoding = $utf8
    [Console]::OutputEncoding = $utf8
    $OutputEncoding = $utf8
    $entry = Join-Path -Path $PSScriptRoot -ChildPath 'invoke-request.mjs'
    $arguments = @($entry, '--request-file', $RequestFile, '--backend', $Backend,
                   '--distribution', $Distribution, '--timeout-ms', [string]$TimeoutMs)
    if ($Workspace) { $arguments += @('--workspace', $Workspace) }
    if ($OutputFile) { $arguments += @('--output-file', $OutputFile) }
    if ($PythonExecutable) { $arguments += @('--python', $PythonExecutable) }
    if ($WslPythonExecutable) { $arguments += @('--wsl-python', $WslPythonExecutable) }
    & node @arguments
    $code = $LASTEXITCODE
} finally {
    [Console]::InputEncoding = $previousInput
    [Console]::OutputEncoding = $previousOutput
    $OutputEncoding = $previousPipe
}
exit $code
