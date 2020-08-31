# Pass an array of intel IDs and this will initate quickScans on the configured computer groups below
#Nathaniel Nieuwendam


#placeholder for intel ID to quick scan. You may define this with the param -intelIdArray
param (
    $intelIdArray = @(394,401)
)

Import-Module -Name Microsoft.PowerShell.Security

#create hashtable for computer groups and associated ID
$allGroupsForQS = @{
    #CONFIGURE ME:
    "Test Workstations" = 628949
    "Test Servers" = 628948
}
#populate with name in the same order as above group
$allGroupsNames = @("Test Workstations","Test Servers")
#Tanium app server hostname
[string]$ServerURI = "https://ServerName-or-IP"
#create global variables
[hashtable]$Script:sessionHeader = @{}
[string]$Global:fullHostname = ""
[string]$Global:badHash = ""
[string]$Global:filePathCheck = ""
[string]$Global:fileDownloadSpath = ""
$Global:fileDownloadID = ""
$returnQuickscanHashtable = @{}



function GetNewSessionID{

    
    $LogonAttempt = 0
    $APIattempt = 0
    $SessionID = "0"
    while($LogonAttempt -le 3 -and $APIattempt -le 3){
        if($SessionID.length -gt 70){break}

        try{$Global:credential = Get-Credential $env:USERNAME}
        catch{$LogonAttempt++}

        # Call login API
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        
        try{$SessionID = Invoke-RestMethod -Uri $ServerURI/auth -Method Post -Credential $Global:credential}
        catch{$APIattempt++}
    }
    if($LogonAttempt -eq 4 -or $APIattempt -eq 4){Write-Host "Failed to logon, exiting...";pause;exit}

    #Store session ID into header
    $sessionHeader1 = @{ 'session' = $SessionID
                        'Accept' = '*/*'
                        'Content-Type' = 'application/json;charset=UTF-8'}
    return $sessionHeader1

    

}
function GetComputerGroups($APIheader) {
    Try{$PREserverResponse = Invoke-RestMethod -Uri $ServerURI/api/v2/groups -Method Get -Headers $APIheader}
    Catch{
        Write-Host "`nAPI call failed, did your session key expire?`n"
        if($error[0].ErrorDetails.Message -match "HTTP 401: Unauthorized."){
            Try{$Script:sessionHeader = GetNewSessionID}
            Catch{
                Write-Host "`nBad Credentials...`n";pause;exit}
            Write-Host $Script:sessionHeader.session
            $APIheader = $Script:sessionHeader
            Try{$PREserverResponse = Invoke-RestMethod -Uri $ServerURI/api/v2/groups -Method Get -Headers $APIheader}
            Catch{
                Write-Host "Failed to get computer groups! Check your creds..."
                return 47
            }
        }
        else{
            Write-Host "Failed to retreive computer groups! Check your API submit..."
            return 47
        }

    }

    $serverResponse = $PREserverResponse.data
    $formattedCGout = @{}
    $dupGroupID = "r"
    #Parse thru the data stopping at each name object to store the previous id with the current name.
    #ID will always preceed the name, so this should always be accurate.
    foreach($groupID in $serverResponse){
            $textCheck = $groupID.text
            try{$textCheck = $textCheck.trim()}
            catch{}
            $andFlag = $groupID.and_flag
            $valueSTORE = $groupID.name
            if($textCheck -eq "Computer Name contains $rawCompName"){
                Write-Host "`nFound an exsisting computer group named:" $valueSTORE
                Write-Host "Use this exsisting computer group for scans and depoyment?"
                $groupIDchoice = Read-Host -Prompt "`nUse $valueSTORE as set computer group? (y/n)"
                if($groupIDchoice -match "y"){
                    $dupGroupID = $groupID.id
                }
            }
            if($valueSTORE -is [string] -and $andFlag -eq "True"){
                try{$formattedCGout.add($groupID.name, $groupID.id)}
                catch{Write-Host "Error adding" $groupID.name ". Duplicate computer group maybe?";pause}

                #set name to NULL, so only the next name will stop the loop
                $valueSTORE = $null
            }
            


    }
    if($dupGroupID -ne "r"){
        $formattedCGout = GetSingleComputerGroup $APIheader $dupGroupID
    }


    return $formattedCGout

}
function StartQuickscan($computerGroup,$intelID){
    $quickscanJson = @{
        "computerGroupId" = $computerGroup
        "intelDocId" = $intelID
    }
    $quickscanJson = $quickscanJson | ConvertTo-Json -Depth 10
    Try{$PREserverResponse = Invoke-RestMethod -Uri $ServerURI/plugin/products/detect3/api/v1/quick-scans -Method Post -Headers $Global:sessionHeader -Body $quickscanJson}
    Catch{Write-Host "`nsubmission call failed, did your session key expire?`n";$Error[0]
        if( $($error[0].ErrorDetails.Message | ConvertFrom-Json).error -match "intel is too large for quick scan"){
            Write-host "Intel doc is too large for quick scan. Skipping...."
            pause
            break
        }
        Try{$Global:sessionHeader = GetNewSessionID}
        Catch{Write-Host "Try again...";$Global:sessionHeader = GetNewSessionID}
        Write-Host $Global:sessionHeader
        
        Try{$PREserverResponse = Invoke-RestMethod -Uri $ServerURI/plugin/products/detect3/api/v1/quick-scans -Method Post -Headers $Global:sessionHeader -Body $quickscanJson}
        Catch{Write-Host "Ok still failing. You suck. Exiting.....";$Error[0];pause;exit}
    }


    $serverResponse = $PREserverResponse
    Write-Host -NoNewline "Started Quickscan: " 
    Write-Host -NoNewline -ForegroundColor Cyan $serverResponse.id 
    Write-Host -NoNewline " succesfully with Question ID: " 
    Write-Host -NoNewline -ForegroundColor Green $PREserverResponse.questionId  
    Write-Host "!!"

    return $serverResponse
}
function CheckQuickscan($quickScanId){
    Try{$PREserverResponse = Invoke-RestMethod -Uri $ServerURI/plugin/products/detect3/api/v1/quick-scans -Method GET -Headers $Global:sessionHeader}
    Catch{Write-Host "`nsubmission call failed, did your session key expire?`n";$Error[0]
        Try{$Global:sessionHeader = GetNewSessionID}
        Catch{Write-Host "Try again...";$Global:sessionHeader = GetNewSessionID}
        Write-Host $Global:sessionHeader
        
        Try{$PREserverResponse = Invoke-RestMethod -Uri $ServerURI/plugin/products/detect3/api/v1/quick-scans -Method GET -Headers $Global:sessionHeader}
        Catch{Write-Host "Ok still failing. You suck. Exiting.....";$Error[0];pause;exit}
    }


    $serverResponse = $PREserverResponse
    Write-Host -NoNewline "Quickscan: " 
    Write-Host -NoNewline -ForegroundColor Cyan $serverResponse.id 
    Write-Host -NoNewline " currently has Alert Count: " 
    Write-Host -NoNewline -ForegroundColor Green $PREserverResponse.alertCount  
    Write-Host "!!"

    return $serverResponse
}
function GetIntelName($intelId){
    Try{$PREserverResponse = Invoke-RestMethod -Uri $ServerURI/plugin/products/detect3/api/v1/intels/$intelId -Method GET -Headers $Global:sessionHeader}
    Catch{Write-Host "`nsubmission call failed, did your session key expire?`n";$Error[0]
        Try{$Global:sessionHeader = GetNewSessionID}
        Catch{Write-Host "Try again...";$Global:sessionHeader = GetNewSessionID}
        Write-Host $Global:sessionHeader
        
        Try{$PREserverResponse = Invoke-RestMethod -Uri $ServerURI/plugin/products/detect3/api/v1/intels/$intelId -Method GET -Headers $Global:sessionHeader}
        Catch{Write-Host "Ok still failing. You suck. Exiting.....";$Error[0];pause;exit}
    }


    $serverResponse = $PREserverResponse
    return $serverResponse
}



$Script:sessionHeader = GetNewSessionID
foreach($intelId in $intelIdArray){
    foreach($computerGroupName in $allgroupsNames){
        $intelIdName = GetIntelName $intelId
        Write-Host -NoNewline "Rule: " 
        Write-Host -NoNewline -ForegroundColor Cyan $intelIdName.name
        Write-Host -NoNewline ". Would like to start quick scan on group: " 
        Write-Host -NoNewline -ForegroundColor Yellow $computerGroupName  
        Write-Host "."
        Read-Host -Prompt "Press enter to start Quick Scan on group $computerGroupName..."

        $curQuickScanId = StartQuickscan $allgroupsForQS[$computerGroupName] $intelId
        $returnQuickscanHashtable[$curQuickScanId.id] = $curQuickScanId.questionId
    }
}













    



