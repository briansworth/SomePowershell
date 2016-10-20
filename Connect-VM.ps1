<#
.SYNOPSIS
    Connect to a virtual machine session.

.DESCRIPTION
    Connects to Virtual machines on a given computer.
    It will connect as if you were in Hyper-V Manager and Connected to a VM.

.EXAMPLE
    Connect-VM -VmName Win7 -ComputerName LocalHost

    This command connects to a Virtual Machine named 'Win7' on localhost.
.EXAMPLE
    Connect-VM -VMId 36dd48e7-c35c-4b91-966b-c71377ee16d0 -ComputerName host01

    This command will use the VMID instead of the VMname.
    It also can connect to a computer other than the localhost
.EXAMPLE
    $VM = Get-VM Win10
    $VM | Connect-VM

    The first command will retrieve the Virutal Machine object 'Win10'
    You can then pipe that VM Object to Connect-VM.
    This command also defaults to 'localhost' as the computername/host.

.Parameter VMName
    The name of a Virtual Machine in Hyper-V. Not necessarilly the hostname.

.Parameter VMId
    The GUID/VMId of a virtual Machine in Hyper-V.
#>
Function Connect-VM {
    [CmdletBinding(DefaultParameterSetName="VMName")]
    Param(
        [Parameter(
            Mandatory=$true,
            Position=0,
            ParameterSetName='VMName',
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true
        )]
        [String]$VMName,

        [Parameter(
            Mandatory=$true,
            Position=0,
            ParameterSetName='Id',
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true
        )]
        [alias('Id')]
        [Guid]$VMId,
        [Parameter(
            Position=0,
            ValueFromPipelineByPropertyName=$true
        )]
        [ValidateNotNullOrEmpty()]
        [String]$ComputerName = 'localhost'
    )
    Begin{
    }
    Process{
        if($PSBoundParameters.ContainsKey('VMName')){
            Write-Verbose "Connecting to VMName [$VMName]"
            vmconnect.exe $ComputerName $VMName
            $VMName=$null
        }elseif($PSBoundParameters.ContainsKey('VMId')){
            Write-Verbose "Connecting to VMId [$VMId]"
            vmconnect.exe $ComputerName -g $VMId
            Remove-Variable VMId
        }
    }
    End{
    }
}