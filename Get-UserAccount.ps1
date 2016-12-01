function GetIDType ([String]$identity){
    [String]$rootDSE=([ADSI]"").distinguishedName
    [String]$guidRegex="^[{(]?[0-9A-F]{8}[-]?([0-9A-F]{4}[-]?){3}[0-9A-F]{12}[)}]?$"
    [String]$idType=''
    switch -Regex ($identity) {
        "$rootDSE" {$idType='distinguishedName'}
        "[@]" {$idType='mail'}
        "$guidRegex" {$idType='objectGuid'}
        "^S-\d-\d+-(\d+-){1,14}\d+$" {$idType='objectSid'}
        Default {$idType='sAMAccountName'}
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

function GetUserSchemaProperties{
    $schema=[DirectoryServices.ActiveDirectory.ActiveDirectorySchema]::GetCurrentSchema()
    [DirectoryServices.ActiveDirectory.ActiveDirectorySchemaClass]$uc=$schema.FindClass('user')

    #searching for these properties results in an error
    ##an error also occurs when including these properties in get-aduser
    [Collections.ArrayList]$exclude=@(
        'tokenGroups',
        'tokenGroupsGlobalAndUniversal',
        'tokenGroupsNoGCAcceptable',
        'msds-memberOfTransitive',
        'msds-memberTransitive'
    )
    [Collections.ArrayList]$allProps=$uc.GetAllProperties()
    #need this and the additional .RemoveAt($index) for PS v2 compatibility
    [Collections.ArrayList]$allPropName=$allProps | Select -expand Name
    #remove the exclude entries from the returned collection
    foreach($entry in $exclude){
        [int32]$index=$allPropName.IndexOf($entry)
        if($index -ne -1){
            $allProps.RemoveAt($index)
            $allPropName.RemoveAt($index)
        }
    }
    return $allProps
}

function isUserPropertyValid([String[]]$properties){
    [Collections.ArrayList]$schema=GetUserSchemaProperties
    [Collections.ArrayList]$schemaNames=$schema | foreach{
        $_.Name.ToLower()
    }
    foreach($prop in $properties){
        if(!($schemaNames.Contains($prop.ToLower()))){
            return $false
        }
    }
    return $true
}

function NewLDAPFilter([String]$identity,[String]$idType) {
    if($idType -eq 'mail' -and $identity -notmatch '^SMTP:'){
        $identity="SMTP:$identity"
    }elseif($idType -eq 'objectGuid'){
        $identity=GuidToLDAPString $identity
    }
    [String]$filter="(&(objectClass=user)($idType=$identity))"
    return $filter
}

function isAccountEnabled ([int32]$userAccountControl){
    if ((2 -band $userAccountControl) -ne 0){
        return $false
    }else{
        return $true
    }
}

function LDAPQuery {
    [CmdletBinding()]
    Param(
    [String]$identity,
    
    [String[]]$properties,

    [String]$searchBase
    )

    [String]$idType=GetIDType -identity $identity
    [String]$filter=NewLDAPFilter -identity $identity -idType $idType
    $search=New-Object -TypeName DirectoryServices.DirectorySearcher
    $search.SearchScope='Subtree'
    $search.SearchRoot=$searchBase
    $search.Filter=$filter
    if($PSBoundParameters.ContainsKey('properties')){
        if($properties -eq '*'){
            $properties=GetUserSchemaProperties | Select -expand Name
        }
        if(!(isUserPropertyValid -properties $properties)){
            [String]$msg="One or more of the properties is invalid"
            Write-Error -Message $msg -ErrorAction Stop
        }
        foreach($p in $properties){
            [void]$search.PropertiesToLoad.Add($p)
        }
    }
    [PSObject]$user=$search.FindOne()
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
    return $user
}

function getSearchBase {
    [CmdletBinding()]
    Param(
        [AllowNull()]
        [String]$searchBase
    )
    if (!$searchBase){
            [String]$searchBase="LDAP://$(([ADSI]'').distinguishedName)"
        if ($searchBase -eq 'LDAP://'){
            [String]$msg='Connection to domain could not be made.'
            Write-Error -Message $msg `
                -Category ConnectionError `
                -ErrorAction Stop
        }
    }
}

function Get-UserAccount {
    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory=$true,
            Position=0,
            ValueFromPipeline=$true
        )]
        [String]$identity,

        [Parameter(Position=1)]     
        [String[]]$properties,

        [Parameter(Position=2)]
        [String]$searchBase=$null
    )
    Begin{}
    Process{
        [String]$regex='\*'
        if ($identity -match $regex){
            Write-Error -Message 'Wildcards (*) are not supported' `
                -ErrorAction Stop
        }
        [Collections.HashTable]$ldapParam=@{
            'identity'=$identity;
            'ErrorAction'='Stop';
        }
        if($PSBoundParameters.ContainsKey('properties')){
            $ldapParam.Add('properties',$properties)
        }
        [DirectoryServices.SearchResult]$result=LDAPQuery @ldapParam
        [DirectoryServices.DirectoryEntry]$entry=$result | Select -expand Path

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
        }
        if($PSBoundParameters.ContainsKey('properties')){
            if($properties -eq '*'){
                Write-Debug 'Properties eq *'
                $properties=GetUserSchemaProperties | Select -expand Name
            }
            [Collections.HashTable]$hash=$result | Select -expand Properties
            foreach($p in $properties){
                $value=$($hash.$($p.ToLower()) | Select -expand $_)
                if(!$value){
                    continue
                }
                Add-Member -MemberType NoteProperty `
                  -InputObject $out `
                  -Name $p `
                  -Value $value `
                  -Force
            }
        }
        Write-Output $out
    }
    End{}
}
