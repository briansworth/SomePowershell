function GetIDType ([String]$identity){
    [String]$rootDSE=([ADSI]"").distinguishedName
    [String]$guidRegex="^[{(]?[0-9A-F]{8}[-]?([0-9A-F]{4}[-]?){3}[0-9A-F]{12}[)}]?$"
    [String]$idType=''
    switch -Regex ($identity) {
        "$rootDSE" {$idType='dn'}
        "[@]" {$idType='mail'}
        "$guidRegex" {$idType='guid'}
        "^S-\d-\d+-(\d+-){1,14}\d+$" {$idType='sid'}
        Default {$idType='samAccountName'}
    }
    return $idType
}

function GuidToLDAPString([Guid]$guid) {
     [Byte[]]$byteArray=$guid.ToByteArray()
     [String]$byteStr=''
     foreach ($byte in $byteArray) {
          $byteStr+='\' + "{0:x}" -f $byte
     }
     return $byteStr
}

function ConvertBytesToSID ([Byte[]]$byteArr){
    $sid=New-Object `
      -TypeName Security.Principal.SecurityIdentifier($byteArr,0)
    return $sid
}

function NewLDAPFilter([String]$identity,[String]$idType) {
    [Text.StringBuilder]$filter='(&(objectClass=user)('
    switch ($idType){
        'dn' {
            [void]$filter.Append('distinguishedName=')
        }
        'mail' {
            [void]$filter.Append('proxyAddresses=SMTP:')
        }
        'guid' {
            $identity=GuidToLDAPString -guid $identity
            [void]$filter.Append('objectGuid=')
        }
        'sid' {
            [void]$filter.Append('objectSid=')
        }
        Default {
            [void]$filter.Append('samaccountname=')
        }
    }
    [void]$filter.Append("$identity))")

    return $filter.ToString()
}

function isAccountEnabled ([int32]$userAccountControl){
    if ((2 -band $userAccountControl) -ne 0){
        return $false
    }else{
        return $true
    }
}

function LDAPQuery ([String]$identity){
    [String]$idType=GetIDType -identity $identity
    [String]$rootDSE="LDAP://$(([ADSI]'').distinguishedName)"
    [String]$filter=NewLDAPFilter -identity $identity -idType $idType
    $search=New-Object -TypeName DirectoryServices.DirectorySearcher
    $search.SearchScope='Subtree'
    $search.SearchRoot=$rootDSE
    $search.Filter=$filter
    [PSObject]$user=$search.FindAll()
    if(!$user){
        [String]$msg=[String]::Format(
            'No user found with identity: {0}. Filter used: {1}',
            "[$identity]",
            "[$filter]"
        )
        Write-Error -Message $msg `
            -TargetObject $identity `
            -Category ObjectNotFound `
            -ErrorAction Stop
    }
    [DirectoryServices.DirectoryEntry]$entry=$user.Path
    return $entry
}

function Get-UserAccount {
    [CmdletBinding()]
    Param(
        [String]$identity
    )
    Begin{}
    Process{
        [String]$regex='\*'
        if ($identity -match $regex){
            Write-Error -Message 'Wildcards (*) are not supported' `
                -ErrorAction Stop
        }
        [DirectoryServices.DirectoryEntry]$entry=LDAPQuery -identity $identity
        [bool]$enabled=isAccountEnabled `
          -userAccountControl $entry.userAccountControl.Value

        $out=New-Object -TypeName PSObject -Property @{
            DistinguishedName=$entry.distinguishedName.Value;
            Name=$entry.name.Value;
            GivenName=$entry.givenName.Value;
            Surname=$entry.sn.Value;
            Enabled=$enabled;
            SID=(ConvertBytesToSID -byteArr $entry.objectSid.Value);
            SamAccountName=$entry.sAMAccountName.Value;
            ObjectGuid=$([Guid]$entry.objectGuid.Value);
            UserPrincipalName=$entry.userPrincipalName.Value;
            PrimarySMTPAddress=$null;
        }
        if ($entry.proxyAddresses){
            [String]$mail=$((($entry.proxyAddresses | 
                Where {$_ -clike 'SMTP:*'}) -replace 'smtp:',''))
            if ($mail){
                $out.PrimarySMTPAddress=$mail
            }
        }
        Write-Output $out
    }
    End{}
}