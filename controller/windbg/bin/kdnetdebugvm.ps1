#
# Argument initialization
#

$nextarg = "none"
$DebugPort = "unassigned"
$targetcomputer = "."
$VMName = ""
$VMGuid = ""
$AutoAssign = "false"
$DebugOff = "false"

function funHelp()
{
$helpText=@"

DESCRIPTION:
NAME: kdnetdebugvm.ps1
Displays (and optionally sets) the port used to network debug a VM.

PARAMETERS: 
-computerName Specifies the name of the computer on which to run the script
-help         Displays help
-vmname       (optional) Name of the VM of interest
-vmguid       (optional) GUID of the VM of interest
-port         (optional) Network port to use for debugging
-debugoff
-autoassign

Either vmname or vmguid must be specified to identify the VM, but not both.
Note that vmname may not uniquely identify the VM, but vmguid does.

SYNTAX:
kdnetdebugvm.ps1 [-computerName targetcomputer] [-vmname NameOfVM] [-vmguid GuidOfVM] [-port PortNumber]

"@
$helpText
exit
}


foreach ($argument in $args)
{
    # parse commands with no following arguments
    switch ($argument)
    {
        "?"     {funHelp}
        "help"  {funHelp}
        "-help" {funHelp}
        "/?"    {funHelp}
        "-?"    {funHelp}
        "autoassign"    {$AutoAssign = "true"}
        "-autoassign"   {$AutoAssign = "true"}
        "/autoassign"   {$AutoAssign = "true"}
        "debugoff"        {$DebugOff = "true"}
        "-debugoff"       {$DebugOff = "true"}
        "/debugoff"       {$DebugOff = "true"}
        default {}
    }

    # parse values that followed a switch

    switch ($nextarg)
    {
        "vmname"        {$VMName = $argument}
        "-vmname"       {$VMName = $argument}
        "/vmname"       {$VMName = $argument}
        "vmguid"        {$VMGuid = $argument}
        "-vmguid"       {$VMGuid = $argument}
        "/vmguid"       {$VMGuid = $argument}
        "port"          {$DebugPort = $argument}
        "-port"         {$DebugPort = $argument}
        "/port"         {$DebugPort = $argument}
        "computername"  {$targetcomputer = $argument}
        "-computername" {$targetcomputer = $argument}
        "/computername" {$targetcomputer = $argument}
        default         {}
    }

    $nextarg = $argument
}

if (($VMName -eq "") -and ($VMGuid -eq ""))
{
    funHelp
}

if (($VMName -ne "") -and ($VMGuid -ne ""))
{
    funHelp
}

$ns = "root\virtualization\v2"
$VMWPName = "$env:windir\system32\vmwp.exe"

#Get a VMManagementService object
$VMManagementService = gwmi -class "Msvm_VirtualSystemManagementService" -namespace $ns -computername $targetcomputer

#Get the VM object that we want to modify
if ($VMName -ne "")
{
    $VM = Get-VM -computername $targetcomputer -VMName $VMName
}

if ($VMGuid -ne "")
{
    $VM = Get-VM -computername $targetcomputer -Id $VMGuid
}

#Get the VirtualSystemGlobalSettingData of the VM we want to modify
$VMSystemGlobalSettingData = gwmi -namespace $ns -computername $targetcomputer -class Msvm_VirtualSystemSettingData | ? { $_.ConfigurationID -eq $VM.Id }

# Set a new debugport
if ($DebugPort -ne "unassigned")
{
    #Change the ElementName property
    $VMSystemGlobalSettingData.DebugPort = $DebugPort
    $VMSystemGlobalSettingData.DebugPortEnabled = 1

    $VMManagementService.ModifySystemSettings($VMSystemGlobalSettingData.GetText(1))
    $FWRuleName = "SynthDebugInboundRule-$DebugPort"
    New-NetFirewallRule -DisplayName $FWRuleName -Program $VMWPName -Protocol UDP -Action Allow -Direction Inbound -LocalPort $DebugPort
}

# Enable auto assigned debug ports
if ($AutoAssign -ne "false")
{
    #Change the ElementName property
    $VMSystemGlobalSettingData.DebugPortEnabled = 2
    $VMManagementService.ModifySystemSettings($VMSystemGlobalSettingData.GetText(1))
    Write-Host -Foreground Yellow "Firewall Ports for autoassign mode can be opened only after the VM is started."
}

# Turn off debugging
if ($DebugOff -ne "false")
{
    $DebugPort = $VMSystemGlobalSettingData.DebugPort
    #Change the ElementName property
    $VMSystemGlobalSettingData.DebugPortEnabled = 0
    $VMSystemGlobalSettingData.DebugPort = 0
    $VMManagementService.ModifySystemSettings($VMSystemGlobalSettingData.GetText(1))
    # May throw an exception if the rule did not exist already.
    # If two rules exist with the same name, both will be deleted.
    if ($DebugPort -ne 0)
    {
        $FWRuleName = "SynthDebugInboundRule-$DebugPort"
        Remove-NetFirewallRule -DisplayName $FWRuleName
    }
}

$VMSystemGlobalSettingData

exit

# SIG # Begin signature block
# MIIl9gYJKoZIhvcNAQcCoIIl5zCCJeMCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDbHDLYuqp9Du8W
# ZSYoLwjEyhkYywkzwemxEtpUqBqajKCCC3YwggT+MIID5qADAgECAhMzAAAEOnXl
# L54LKZgeAAAAAAQ6MA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTAwHhcNMjEwOTAyMTgyNTU5WhcNMjIwOTAxMTgyNTU5WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQCY3ZRqR2tCWlzzYBfCE+xMH9h9GCeu04bOvwI1CsmGgdlQ1B5fbCPJ8pV/VDm6
# z4AcpCyzFY9IjHTLvvQ/cWDJ9xurqK/7x2d+LjTUoNne2hvDs0ZPLhmRRPE9F23b
# w10OqgRQYk0OxDbQTWywWuMRc0VQ/RzoxwFZqISKEauTYExug0yD92+EWxzaP7BZ
# 72OEyl8pgCZQZhgWae0LjPTJ1WSqWYYgtt9ufFPDgo1C5c48+bIoXY0/Ata8xrpH
# 3EH3xDCjvML0c54l5sxNCLNvFvlZ1bXGfxrEXvQz4yQryw6Pzfl8w7C28tJeH4P6
# DCj23HctVLUY4IvBD6S96sP9AgMBAAGjggF9MIIBeTAfBgNVHSUEGDAWBgorBgEE
# AYI3PQYBBggrBgEFBQcDAzAdBgNVHQ4EFgQUT6htXeJskyl+QI1fDZCM77mf3Ssw
# VAYDVR0RBE0wS6RJMEcxLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJh
# dGlvbnMgTGltaXRlZDEWMBQGA1UEBRMNMjMwODY1KzQ2NzM5OTAfBgNVHSMEGDAW
# gBTm/F97uyIAWORyTrX0IXQjMubvrDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8v
# Y3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNDb2RTaWdQQ0Ff
# MjAxMC0wNy0wNi5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY0NvZFNpZ1BDQV8yMDEw
# LTA3LTA2LmNydDAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQBZbJS5
# 9zc0vbkPcmCYIph5c1ew/OKA/n3lTKQnchxnFw7MPLy2lG9q79wbdZ63EjiCF/8K
# B/XWBx6dAAk4P1yUjOeNCIJ6j9cNjEQ0xbw56uJkB16lV6q90OWmCj0319qJ0xw6
# tia0rR5c9y0NS0w91S86ztLC6O/ws+w2303OCmUNH0Bsbfs+YIwdvjgFimIcSqMf
# wpwszhSa/FXu8/wUvL+EAAE+ztz08rXM58/04/GIJ9a90mPE9fcrZDrOxOf53b+t
# jBebeOx7ncKvfvc6q2uT+uhjICZNOBMrXiYVD4i50HxUKBd9TaclXq5t3Pg6TIWN
# v0YXWqWodTiZ9KEQMIIGcDCCBFigAwIBAgIKYQxSTAAAAAAAAzANBgkqhkiG9w0B
# AQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAG
# A1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAw
# HhcNMTAwNzA2MjA0MDE3WhcNMjUwNzA2MjA1MDE3WjB+MQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQgQ29kZSBT
# aWduaW5nIFBDQSAyMDEwMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
# 6Q5kUHlntcTj/QkATJ6UrPdWaOpE2M/FWE+ppXZ8bUW60zmStKQe+fllguQX0o/9
# RJwI6GWTzixVhL99COMuK6hBKxi3oktuSUxrFQfe0dLCiR5xlM21f0u0rwjYzIjW
# axeUOpPOJj/s5v40mFfVHV1J9rIqLtWFu1k/+JC0K4N0yiuzO0bj8EZJwRdmVMkc
# vR3EVWJXcvhnuSUgNN5dpqWVXqsogM3Vsp7lA7Vj07IUyMHIiiYKWX8H7P8O7YAS
# NUwSpr5SW/Wm2uCLC0h31oVH1RC5xuiq7otqLQVcYMa0KlucIxxfReMaFB5vN8sZ
# M4BqiU2jamZjeJPVMM+VHwIDAQABo4IB4zCCAd8wEAYJKwYBBAGCNxUBBAMCAQAw
# HQYDVR0OBBYEFOb8X3u7IgBY5HJOtfQhdCMy5u+sMBkGCSsGAQQBgjcUAgQMHgoA
# UwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQY
# MBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6
# Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1
# dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0
# dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0XzIw
# MTAtMDYtMjMuY3J0MIGdBgNVHSAEgZUwgZIwgY8GCSsGAQQBgjcuAzCBgTA9Bggr
# BgEFBQcCARYxaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL1BLSS9kb2NzL0NQUy9k
# ZWZhdWx0Lmh0bTBABggrBgEFBQcCAjA0HjIgHQBMAGUAZwBhAGwAXwBQAG8AbABp
# AGMAeQBfAFMAdABhAHQAZQBtAGUAbgB0AC4gHTANBgkqhkiG9w0BAQsFAAOCAgEA
# GnTvV08pe8QWhXi4UNMi/AmdrIKX+DT/KiyXlRLl5L/Pv5PI4zSp24G43B4AvtI1
# b6/lf3mVd+UC1PHr2M1OHhthosJaIxrwjKhiUUVnCOM/PB6T+DCFF8g5QKbXDrMh
# KeWloWmMIpPMdJjnoUdD8lOswA8waX/+0iUgbW9h098H1dlyACxphnY9UdumOUjJ
# N2FtB91TGcun1mHCv+KDqw/ga5uV1n0oUbCJSlGkmmzItx9KGg5pqdfcwX7RSXCq
# tq27ckdjF/qm1qKmhuyoEESbY7ayaYkGx0aGehg/6MUdIdV7+QIjLcVBy78dTMgW
# 77Gcf/wiS0mKbhXjpn92W9FTeZGFndXS2z1zNfM8rlSyUkdqwKoTldKOEdqZZ14y
# jPs3hdHcdYWch8ZaV4XCv90Nj4ybLeu07s8n07VeafqkFgQBpyRnc89NT7beBVaX
# evfpUk30dwVPhcbYC/GO7UIJ0Q124yNWeCImNr7KsYxuqh3khdpHM2KPpMmRM19x
# HkCvmGXJIuhCISWKHC1g2TeJQYkqFg/XYTyUaGBS79ZHmaCAQO4VgXc+nOBTGBpQ
# HTiVmx5mMxMnORd4hzbOTsNfsvU9R1O24OXbC2E9KteSLM43Wj5AQjGkHxAIwlac
# vyRdUQKdannSF9PawZSOB3slcUSrBmrm1MbfI5qWdcUxghnWMIIZ0gIBATCBlTB+
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9N
# aWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQSAyMDEwAhMzAAAEOnXlL54LKZgeAAAA
# AAQ6MA0GCWCGSAFlAwQCAQUAoIIBBDAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIB
# BDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg
# 9dqdhF4OR7gDjF8vJdrLT9KZqbWkhiPfaXbvLkc5VLgwPAYKKwYBBAGCNwoDHDEu
# DCxzUFk3eFBCN2hUNWc1SEhyWXQ4ckRMU005VnVaUnVXWmFlZjJlMjJSczU0PTBa
# BgorBgEEAYI3AgEMMUwwSqAkgCIATQBpAGMAcgBvAHMAbwBmAHQAIABXAGkAbgBk
# AG8AdwBzoSKAIGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS93aW5kb3dzMA0GCSqG
# SIb3DQEBAQUABIIBAA3RKjGwGI6xBYo7sJWN7uQcgWe5BljQAkOE/1CpvdKtx57I
# cvgwIu69ua1KtGM1/hg4/KgB8GDoFYySNuxtaK8WRQdVYOu9PyWPco0SoBrsMDOB
# 5vwtVeiMheSgiJxxz/Sl1YgWI5nQfSvMHFDLOWpgAQYa7sO0dPHJ0CJZeHfW+dWk
# 5hhr01EYTPdRYVVmQBqMUMMojhc8tA6WAHTv5dmF8rGFtY8RNHQf5ZmupQtvJQAg
# IbF9BEfHQE6I5PrxTYh4+ZLcAylTXDtAMQbvlkBsx5IUuyS2cEc7PlWoREjRPBqz
# f4O4kqP+PQZCNGWVgIONuJNszchIVmt3xHlf4K2hghcJMIIXBQYKKwYBBAGCNwMD
# ATGCFvUwghbxBgkqhkiG9w0BBwKgghbiMIIW3gIBAzEPMA0GCWCGSAFlAwQCAQUA
# MIIBVQYLKoZIhvcNAQkQAQSgggFEBIIBQDCCATwCAQEGCisGAQQBhFkKAwEwMTAN
# BglghkgBZQMEAgEFAAQgLAjnE4JQgvJJEOAh7LQ5grzAvOzvL4PMiE+CE1FkPE0C
# BmJrR4+1kRgTMjAyMjA1MDYyMjMyNDEuMzE3WjAEgAIB9KCB1KSB0TCBzjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9z
# b2Z0IE9wZXJhdGlvbnMgUHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
# RVNOOkY3QTYtRTI1MS0xNTBBMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBTZXJ2aWNloIIRXDCCBxAwggT4oAMCAQICEzMAAAGlAN4IxEAHcU4AAQAAAaUw
# DQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcN
# MjIwMzAyMTg1MTE5WhcNMjMwNTExMTg1MTE5WjCBzjELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9wZXJhdGlv
# bnMgUHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkY3QTYtRTI1
# MS0xNTBBMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAurGG6CBqSLzC6g4wx3uuwRCe
# YCG1XyJTVjSK2werfRN0JckOa9mNpnzK84dgVWFPIPVvkkYm3BmNbPV+CUKqzHmo
# HE/VbHUJmexDW2JGxFZBzXZWQROaRjzHjoyAewbICaE8+myBGeSUZqLsepAUHfXH
# 9COTHutsCWvo9uUHi06ZpHWcrGXhUiCy0PB+d4pqgQTDiI3/FN3O1mPDIaJjmE2n
# pt562RyLOAkU7f/JEdiHSC2T5tESGuYiBtquuuBvPsyycDu2Uq8Zw72Idzr7azKa
# sBXLcLNDggw08VxNPHzBNn6Sm/qUWzV4bzGV+y7Y0NYqyGsyUofYmljNYBbV8I4P
# mKtewTgs6+LFlC9ud5ATr6IZ8hDBpuP59F2i4BTYCIT6Jo2wgNql0ppvxYvHPpU9
# FsQv4zowWRyyiK4oceiyEKnsmGZn2IzTKsTHZd5s6Fr9dDfjYqxEazaHTaClfrAH
# LJPx4PcwlUjFJGbgwsiKW9Zyl303euihrBstTqB2TuCgpZLr37DaO2i5cIRi3og9
# 9mryV2LQv8LBhu2/uZseYhn05zQkQlzpv2BxUN+g+J6YwpzPXkEt6nLHuelDYyIM
# oixw6oqFe5kj49l6s04eGL++zLb8WP2UHqQmsxhJ9XQXZ+u8FIFcwHvGO/ymCpfl
# BdR7ydPFvhR8nRwMC8ECAwEAAaOCATYwggEyMB0GA1UdDgQWBBRfpo8DAJeurq1w
# 7vvcWRdLaKka3zAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNV
# HR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2Ny
# bC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYI
# KwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAy
# MDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0G
# CSqGSIb3DQEBCwUAA4ICAQCWmwsX5TAwooRHanRYmejgboYYad+DeqMN1odzm69d
# i0boqYeuoB/9ioeSY2i1KvpkQSeUYIlhHtbe4n7lum+PTfAWoZ5+9CwohHb6rpOv
# OjO8/g2yh1ZNPlJWn8LpMQMa4sL2Y5AoDi3IvjQdNbu3FvRwB1+CfIcWgj8Gxmj8
# Vpd7NDyE7jFSOEOnI014npZi9fk0L4e/2eZPLOOrISD8vZxcA6bERa988BDWV/G+
# u1TAbvmMZ5Rp7CSHC3NqcKc/eXpiPAkUoHqfv9Ne2t+KTXFjWSB6/UnBDlpR0/HB
# J0OYYThdM3azqk86Lwg7X305/oAS+HjV4PFHP7XVVRym4afu0lR5JNRIey/NDwQI
# 6PnDvsy/nn8XyFa7Tt6CcbxKtaPn5MXE08KnH8AU2/PP6h1NFNl3gta6iZwwdSYs
# WJQY4B160XpKh8cbkRwWfQNMPVqkFnMI/zGwZBxmDBWqjui/bf+4gmUwIsDJNhlX
# 0hMI/T1yJQlsoFUJA2sYSdD9csU72bKzLINGu8eFTm4Y91fPgm3b9k3slBhG5U1K
# 4Kk3CgrQmvWzpyIO8cR4vKJzPGgh70YfdLJ9sfHq/+mEj6ITcNajVMIrvkQvqm3q
# TmLfr+Sfa5JVd1MfjhlWSHf+KFXe8TCzvy4aW+yIxysoGCmjcd1yMMeIehaxR/gY
# jDCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQEL
# BQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNV
# BAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4X
# DTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgUENBIDIwMTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM
# 57RyIQt5osvXJHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm
# 95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzB
# RMhxXFExN6AKOG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBb
# fowQHJ1S/rboYiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCO
# Mcg1KL3jtIckw+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYw
# XE8s4mKyzbnijYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW
# /aUgfX782Z5F37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/w
# EPK3Rxjtp+iZfD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPK
# Z6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2
# BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfH
# CBUYP3irRbb1Hode2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYB
# BAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8v
# BO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYM
# KwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEF
# BQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBW
# BgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUH
# AQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtp
# L2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsF
# AAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518Jx
# Nj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+
# iehp4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2
# pFaq95W2KFUn0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefw
# C2qBwoEZQhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7
# T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFO
# Ry3BFARxv2T5JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhL
# mm77IVRrakURR6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3L
# wUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5
# m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE
# 0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLPMIICOAIB
# ATCB/KGB1KSB0TCBzjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEpMCcGA1UECxMgTWljcm9zb2Z0IE9wZXJhdGlvbnMgUHVlcnRvIFJpY28xJjAk
# BgNVBAsTHVRoYWxlcyBUU1MgRVNOOkY3QTYtRTI1MS0xNTBBMSUwIwYDVQQDExxN
# aWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQCzyXDb
# RbObEMqI3UuGHuZlZe60qKCBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QSAyMDEwMA0GCSqGSIb3DQEBBQUAAgUA5h+pCzAiGA8yMDIyMDUwNjE4MDI1MVoY
# DzIwMjIwNTA3MTgwMjUxWjB0MDoGCisGAQQBhFkKBAExLDAqMAoCBQDmH6kLAgEA
# MAcCAQACAg2OMAcCAQACAhHAMAoCBQDmIPqLAgEAMDYGCisGAQQBhFkKBAIxKDAm
# MAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcN
# AQEFBQADgYEAYQid+nmeARpMGVVfm1J2Fs3NAeTUkzd8Ezq/H8cTA2v2sfxZtTSA
# oRrpANc9ZQN6U/e83YFSoUjUxpBd6ufO/UiwhiWOxqtpFDejW+XUp62X+zcQtJcL
# ZHd8/VyuNgqKRZ2Dj5RQ9AzhTaZS3qsJ5kgQJFXMcs3zfa5LZQlTkd0xggQNMIIE
# CQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAaUA3gjE
# QAdxTgABAAABpTANBglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqG
# SIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCBrxh9yuhCU87DHiJmB7eUPs4e2rFQy
# NPAO8fTo7YohEDCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EILgKOHF+ZgSx
# oK3YBTzcqGH7okeXKTcHvS98wcyUEtxcMIGYMIGApH4wfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTACEzMAAAGlAN4IxEAHcU4AAQAAAaUwIgQgGBbYfD6VF/RC
# W1pksxKs85qFsEjdHhSgkRHfiNlJoK0wDQYJKoZIhvcNAQELBQAEggIArblf4YU7
# RWnW65mLRJny5A9FpOf0CCn9PIr9AHkGxXDJTlMEhvbM80HgQk/RUTJlpkbxO1tf
# Be0Ipc6Kw3wxSrYAeRaXJy9j2WwKbb9rHi2lAc3OvKG2UZGVxC3dd1eVNz1cDBOi
# GlRvh1Dlp7YxdUL2qS0gDPrg06io0TkX1PqejqY5v6MqRpPStk0jT5RR7jrTiUhT
# M3w1QbZ6AGjRq2uOK4KOjqscUnOr96J0VUW2zbv3mssiAGylttxwpym5dgkY62l1
# 92o6V0DspygWzoJiDS8/65menykLdtamtxEfFHcoi9vRFcU21XBSAK/GaU/kZwBc
# fsNoLXhCIUuLRlGwisOgsbemQ/OL7a5nrrzmnHcq7mHWqY6bJumLexQhx1Ll4qST
# NxAwjMcAqeUvtC4jsnUyMRxiJhxACqtsM8yiJrA6sFKBoysDQqklh6qO9wDGWGXh
# ciOH3GDZgbPgjbi/Txs7mLbwtuMWK2XxpJN8ICztEZZlgFHYyIZIKTEso+KyDt2y
# Yp7LB2AEsVf/9LbUarp9MDGAOkUppn0enhQxB33A/lnl0IYN1WPvdFSkZNoHXVw8
# xHqcb1qT7cZMcwpWHe1GeJfxS0qmJqh/zkjS6Jc6MTtOsTGWR8JbxYHMwX8dCdQm
# TBqlU0vfbg8UcFYED8LJ4tkur6b0vakGYAA=
# SIG # End signature block
