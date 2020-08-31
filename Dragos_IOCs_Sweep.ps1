# Retreive Dragos HASHES IOCs and uplaod to Tanium. Optional Quick scans after.
# Nathaniel Nieuwendam


Import-Module -Name Microsoft.PowerShell.Security

$Global:DebugMode = 0
[string]$Global:ServerURI = "https://TaniumServerURI"
[hashtable]$Global:sessionHeader = @{}
[string]$Global:DRAGOSURI = "https://portal.dragos.com"
$Global:DragosHeader = @{
    "API-Token" = "Dragos API token"
    "API-Secret" = "Dragos API secret"
}
#comment out proxy if not required.
[string]$global:proxyServerName = "http://ProxyURI"
$Global:DragosSN = "AA-2020-21"
$Global:DragosUploadAfter = "2020-00-00"

function GetNewSessionID{

    
    $LogonAttempt = 0
    $APIattempt = 0
    $SessionID = "0"
    Write-Host "Welcome to the Dragos IOC uploader, Login first to retreive a Session ID"
    while($LogonAttempt -le 3 -and $APIattempt -le 3){
        if($SessionID.length -gt 70){break}

        try{$Global:credential = Get-Credential $env:USERNAME}
        catch{$LogonAttempt++}

        # Call login API
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        
        try{$SessionID = Invoke-RestMethod -Uri $Global:ServerURI/auth -Method Post -Credential $credential}
        catch{$APIattempt++}
    }
    if($LogonAttempt -eq 4 -or $APIattempt -eq 4){Write-Host "Failed to logon, exiting...";pause;exit}

    Write-Host "Session ID capture SUCCESS!"
    Write-Host $SessionID

    #Store session ID into header
    $sessionHeader1 = @{ 'session' = $SessionID
                        'Accept' = '*/*'
                        'Content-Type' = 'application/json;charset=UTF-8'}
    return $sessionHeader1

    

}
function ProxyLogonCheck(){
    $response = ""
    $proxyInfo = @{
        "proxy" = "$proxyServerName"
        "cred" = ""
        }
    $LogonAttempt = 0
    $APIattempt = 0

    Write-Host "Welcome, Login first to retreive a Session ID"
    while($LogonAttempt -le 4 -and $APIattempt -le 4){
        if($response.StatusCode -eq 200){break}
        else{$APIattempt++}

        try{$Global:credential = Get-Credential $env:USERNAME}
        catch{$LogonAttempt++}

        $proxyInfo.cred = $Global:credential

        # Call login API
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        try{$response = Invoke-WebRequest -Uri $Global:DRAGOSURI/api/v1/products/$Global:DragosSN/stix2 -Headers $DragosHeader -Proxy $proxyInfo.proxy -ProxyCredential $proxyInfo.cred}
        catch{$APIattempt++
            Write-Host "Bad Proxy logon. Try again...."
        }

        try{$contentJson = $response.Content | ConvertFrom-Json}
        catch{$APIattempt++
            Write-Host "Bad Proxy logon. Try again...."
        }

    }
    if($LogonAttempt -eq 4){Write-Host "Failed to logon, exiting...";pause;exit}

    Write-Host "Proxy access granted!"

    return $proxyInfo

}

function GetLatestProducts(){
    try{$DresponsePre = Invoke-WebRequest -Uri $Global:DRAGOSURI/api/v1/products -Headers $Global:DragosHeader -Proxy $Global:proxyInfoSet.proxy -ProxyCredential $Global:proxyInfoSet.cred -Method GET}
    catch{$Error[0];pause}

    $contentCleaned = $DresponsePre.Content | ConvertFrom-Json
    $productArtifacts = $contentCleaned.objects
    return $productArtifacts
}
function IOCbyProductSerial($DSerialNum){
    try{$DresponsePre = Invoke-WebRequest -Uri $Global:DRAGOSURI/api/v1/products/$DSerialNum/stix2 -Headers $Global:DragosHeader -Proxy $Global:proxyInfoSet.proxy -ProxyCredential $Global:proxyInfoSet.cred -Method GET}
    catch{$Error[0];pause}

    $contentCleaned = $DresponsePre.Content | ConvertFrom-Json
    $productArtifacts = $contentCleaned.objects
    return $productArtifacts

}
function MetadatabyProductSerial($DSerialNum){
    try{$DresponsePre = Invoke-WebRequest -Uri $Global:DRAGOSURI/api/v1/products/$DSerialNum -Headers $Global:DragosHeader -Proxy $Global:proxyInfoSet.proxy -ProxyCredential $Global:proxyInfoSet.cred -Method GET}
    catch{Write-Host ""$Error[0];pause}

    $contentCleaned = $DresponsePre.Content | ConvertFrom-Json

    #remove quotes if needed
    <#
    if($contentCleaned.title -match 'original title' -and $contentCleaned.title -match 'original title'){
        $contentCleaned.title = 'Title without quotes'
    }
    #>

    $productArtifacts = $contentCleaned
    return $productArtifacts

}
function IndicatorsMD5HashesOnly($dateLookback){
    try{$DresponsePre = Invoke-WebRequest -Uri $Global:DRAGOSURI/api/v1/indicators?type=md5`&updated_after=$dateLookback -Headers $Global:DragosHeader -Proxy $Global:proxyInfoSet.proxy -ProxyCredential $Global:proxyInfoSet.cred -Method GET}
    catch{$Error[0];pause}

    $contentCleaned = $DresponsePre.Content | ConvertFrom-Json
    $productArtifacts = $contentCleaned.indicators
    return $productArtifacts


}
function IndicatorsSHA256HashesOnly($dateLookback){
    try{$DresponsePre = Invoke-WebRequest -Uri $Global:DRAGOSURI/api/v1/indicators?type=sha256`&updated_after=$dateLookback -Headers $Global:DragosHeader -Proxy $Global:proxyInfoSet.proxy -ProxyCredential $Global:proxyInfoSet.cred -Method GET}
    catch{$Error[0];pause}

    $contentCleaned = $DresponsePre.Content | ConvertFrom-Json
    $productArtifacts = $contentCleaned.indicators
    return $productArtifacts


}

function DragosIOCtoHashTable(){}

#From the UploadQuickAdd
function BuildJsonQuickAdd($name,$indicators,$fileType){
    $quickAddJson = @{
        "name" = "$name"
        "text" = "$indicators"
        "type" = "$fileType"
    }

    return $quickAddJson
}
function SubmitNewQuickAdd($intelDocSubmission){
    $convertedSubmit = $intelDocSubmission | ConvertTo-Json -Depth 10
    Try{$PREserverResponse = Invoke-RestMethod -Uri $ServerURI/plugin/products/detect3/api/v1/intels/quick-add -Method Post -Headers $Global:sessionHeader -Body $convertedSubmit}
    Catch{Write-Host "`nsubmission call failed, did your session key expire?`n";$Error[0]
        Try{$Global:sessionHeader = GetNewSessionID}
        Catch{Write-Host "Try again...";$Global:sessionHeader = GetNewSessionID}
        Write-Host $Global:sessionHeader
        
    Try{$PREserverResponse = Invoke-RestMethod -Uri $ServerURI/plugin/products/detect3/api/v1/intels/quick-add -Method -Headers $Global:sessionHeader -Body $convertedSubmit}
    Catch{Write-Host "Ok still failing. You suck. Exiting.....";$Error[0];pause;exit}
    }
    $serverResponse = $PREserverResponse.OuterXml
    Write-Host -NoNewline "Server Parsed: " 
    Write-Host -NoNewline -ForegroundColor Cyan $PREserverResponse.ioc.short_description 
    Write-Host -NoNewline " Succesfully with ID: " 
    Write-Host -NoNewline -ForegroundColor Yellow $PREserverResponse.ioc.id 
    Write-Host "!!"
    return $serverResponse
}
function SubmitIntelXML($xmlObj){
    $Global:sessionHeader.'Content-Type' = "application/xml"
    Try{$PREserverResponse = Invoke-RestMethod -Uri $ServerURI/plugin/products/detect3/api/v1/intels -Method Post -Headers $Global:sessionHeader -Body $xmlObj}
    Catch{Write-Host "`nsubmission call failed, did your session key expire?`n";$Error[0]
        Try{$Global:sessionHeader = GetNewSessionID}
        Catch{Write-Host "Try again...";$Global:sessionHeader = GetNewSessionID}
        Write-Host $Global:sessionHeader
        
    Try{$PREserverResponse = Invoke-RestMethod -Uri $ServerURI/plugin/products/detect3/api/v1/intels -Method Post -Headers $Global:sessionHeader -Body $xmlObj}
    Catch{Write-Host "Ok still failing. You suck. Exiting.....";$Error[0];pause;exit}
    }
    $serverResponse = $PREserverResponse
    Write-Host -NoNewline "Rule: " 
    Write-Host -NoNewline -ForegroundColor Cyan $serverResponse.name
    Write-Host -NoNewline " Was added succesfully with ID: " 
    Write-Host -NoNewline -ForegroundColor Green $PREserverResponse.id  
    Write-Host "!!"

    $Global:sessionHeader.'Content-Type' = "application/json;charset=UTF-8"
    return $serverResponse
}


#Begin Main


$Global:sessionHeader = GetNewSessionID
$Global:proxyInfoSet = ProxyLogonCheck 

$dayLookback = 60
try{[int]$dayLookback =  Read-Host "How many days to look back? (default 60) "}
catch{}
if($dayLookback -isnot [int]){
$dayLookback = 60
}
$dayLookback = -$dayLookback

$Global:DragosUploadAfter = $(get-date).AddDays($dayLookback)
$Global:DragosUploadAfter = $Global:DragosUploadAfter.ToString("yyyy-MM-dd")

$indicatorsMD5 = IndicatorsMD5HashesOnly $Global:DragosUploadAfter
$indicatorsSHA256 = IndicatorsSHA256HashesOnly $Global:DragosUploadAfter

#Clear global Hashtable for IOCs
$global:badHashes = @{}
$global:productDescrips = @{}
$global:productTitles = @{}
$Global:productTLP = @{}


$finalMD5Count = $indicatorsMD5.Count
Write-Host -NoNewline "Found latest "
Write-Host -NoNewline -ForegroundColor Yellow $finalMD5Count
Write-Host -NoNewline " DRAGOS product. Retreived with " 
Write-Host -NoNewline -ForegroundColor Cyan $finalMD5Count
Write-Host " hashes downloaded."

foreach($singleIOC in $indicatorsMD5){
    $singleIOCname = $singleIOC.products.serial

    if($singleIOCname.count -eq 1 -and $singleIOCname.Length -lt 13){
        if($Global:DebugMode){
            Write-host -NoNewline "Dragos Serial: "
            Write-Host -NoNewline -ForegroundColor Cyan "$singleIOCname"
            Write-Host -NoNewline " Hash the bad hash: "
            Write-Host -ForegroundColor Yellow $singleIOC.value
        }
        $global:badHashes[$singleIOCname] += "$($singleIOC.value),"
    }
    elseif($singleIOCname.count -eq 2){
        if($Global:DebugMode){
            Write-host -NoNewline "Dragos Serial: "
            Write-Host -NoNewline -ForegroundColor Cyan $singleIOCname[0]
            Write-Host -NoNewline " Hash the bad hash: "
            Write-Host -ForegroundColor Yellow $singleIOC.value
        }
        $global:badHashes[$singleIOCname[0]] += "$($singleIOC.value),"
        if($Global:DebugMode){
            Write-host -NoNewline "Dragos Serial: "
            Write-Host -NoNewline -ForegroundColor Cyan $singleIOCname[1]
            Write-Host -NoNewline " Hash the bad hash: "
            Write-Host -ForegroundColor Yellow $singleIOC.value
        }
        $global:badHashes[$singleIOCname[1]] += "$($singleIOC.value),"
    }
    elseif($singleIOCname.count -eq 3){
        if($Global:DebugMode){
            Write-host -NoNewline "Dragos Serial: "
            Write-Host -NoNewline -ForegroundColor Cyan $singleIOCname[0]
            Write-Host -NoNewline " Hash the bad hash: "
            Write-Host -ForegroundColor Yellow $singleIOC.value
        }
        $global:badHashes[$singleIOCname[0]] += "$($singleIOC.value),"
        if($Global:DebugMode){
            Write-host -NoNewline "Dragos Serial: "
            Write-Host -NoNewline -ForegroundColor Cyan $singleIOCname[1]
            Write-Host -NoNewline " Hash the bad hash: "
        }
        $global:badHashes[$singleIOCname[1]] += "$($singleIOC.value),"
        if($Global:DebugMode){
            Write-Host -ForegroundColor Yellow $singleIOC.value
            Write-host -NoNewline "Dragos Serial: "
            Write-Host -NoNewline -ForegroundColor Cyan $singleIOCname[2]
            Write-Host -NoNewline " Hash the bad hash: "
            Write-Host -ForegroundColor Yellow $singleIOC.value
        }
        $global:badHashes[$singleIOCname[2]] += "$($singleIOC.value),"
    }
    elseif($singleIOCname.count -eq 4){
        if($Global:DebugMode){
            Write-host -NoNewline "Dragos Serial: "
            Write-Host -NoNewline -ForegroundColor Cyan $singleIOCname[0]
            Write-Host -NoNewline " Hash the bad hash: "
            Write-Host -ForegroundColor Yellow $singleIOC.value
        }
        $global:badHashes[$singleIOCname[0]] += "$($singleIOC.value),"
        if($Global:DebugMode){
            Write-host -NoNewline "Dragos Serial: "
            Write-Host -NoNewline -ForegroundColor Cyan $singleIOCname[1]
            Write-Host -NoNewline " Hash the bad hash: "
            Write-Host -ForegroundColor Yellow $singleIOC.value
        }
        $global:badHashes[$singleIOCname[1]] += "$($singleIOC.value),"
        if($Global:DebugMode){
            Write-host -NoNewline "Dragos Serial: "
            Write-Host -NoNewline -ForegroundColor Cyan $singleIOCname[2]
            Write-Host -NoNewline " Hash the bad hash: "
            Write-Host -ForegroundColor Yellow $singleIOC.value
        }
        $global:badHashes[$singleIOCname[2]] += "$($singleIOC.value),"
        if($Global:DebugMode){
            Write-host -NoNewline "Dragos Serial: "
            Write-Host -NoNewline -ForegroundColor Cyan $singleIOCname[3]
            Write-Host -NoNewline " Hash the bad hash: "
            Write-Host -ForegroundColor Yellow $singleIOC.value
        }
        $global:badHashes[$singleIOCname[3]] += "$($singleIOC.value),"
    }
    elseif($singleIOCname.length -eq 0){
        $singleIOCname = "JP_LS-$($singleIOC.last_seen.Substring(0,10))"
        if($Global:DebugMode){
            Write-host -NoNewline "Dragos Serial: "
            Write-Host -NoNewline -ForegroundColor Cyan $singleIOCname
            Write-Host -NoNewline " Hash the bad hash: "
            Write-Host -ForegroundColor Yellow $singleIOC.value
        }
        $global:badHashes[$singleIOCname] += "$($singleIOC.value),"
    }
    else{
        pause
    }

}
Write-Host -NoNewline "There were "
Write-Host -NoNewline -ForegroundColor Yellow $global:badHashes.count
Write-Host -NoNewline " DRAGOS product retreived with " 
Write-Host -NoNewline -ForegroundColor Cyan $finalMD5Count
Write-Host " MD5 hashes downloaded."

#Parse the SHA 256
foreach($singleIOC in $indicatorsSHA256){
    $singleIOCname = $singleIOC.products.serial

    if($singleIOCname.count -eq 1 -and $singleIOCname.Length -lt 13){
        if($Global:DebugMode){
            Write-host -NoNewline "Dragos Serial: "
            Write-Host -NoNewline -ForegroundColor Cyan "$singleIOCname"
            Write-Host -NoNewline " Hash the bad hash: "
            Write-Host -ForegroundColor Yellow $singleIOC.value
        }
        $global:badHashes[$singleIOCname] += "$($singleIOC.value),"
    }
    elseif($singleIOCname.count -eq 2){
        if($Global:DebugMode){
            Write-host -NoNewline "Dragos Serial: "
            Write-Host -NoNewline -ForegroundColor Cyan $singleIOCname[0]
            Write-Host -NoNewline " Hash the bad hash: "
            Write-Host -ForegroundColor Yellow $singleIOC.value
        }
        $global:badHashes[$singleIOCname[0]] += "$($singleIOC.value),"
        if($Global:DebugMode){
            Write-host -NoNewline "Dragos Serial: "
            Write-Host -NoNewline -ForegroundColor Cyan $singleIOCname[1]
            Write-Host -NoNewline " Hash the bad hash: "
            Write-Host -ForegroundColor Yellow $singleIOC.value
        }
        $global:badHashes[$singleIOCname[1]] += "$($singleIOC.value),"
    }
    elseif($singleIOCname.count -eq 3){
        if($Global:DebugMode){
            Write-host -NoNewline "Dragos Serial: "
            Write-Host -NoNewline -ForegroundColor Cyan $singleIOCname[0]
            Write-Host -NoNewline " Hash the bad hash: "
            Write-Host -ForegroundColor Yellow $singleIOC.value
        }
        $global:badHashes[$singleIOCname[0]] += "$($singleIOC.value),"
        if($Global:DebugMode){
            Write-host -NoNewline "Dragos Serial: "
            Write-Host -NoNewline -ForegroundColor Cyan $singleIOCname[1]
            Write-Host -NoNewline " Hash the bad hash: "
        }
        $global:badHashes[$singleIOCname[1]] += "$($singleIOC.value),"
        if($Global:DebugMode){
            Write-Host -ForegroundColor Yellow $singleIOC.value
            Write-host -NoNewline "Dragos Serial: "
            Write-Host -NoNewline -ForegroundColor Cyan $singleIOCname[2]
            Write-Host -NoNewline " Hash the bad hash: "
            Write-Host -ForegroundColor Yellow $singleIOC.value
        }
        $global:badHashes[$singleIOCname[2]] += "$($singleIOC.value),"
    }
    elseif($singleIOCname.count -eq 4){
        if($Global:DebugMode){
            Write-host -NoNewline "Dragos Serial: "
            Write-Host -NoNewline -ForegroundColor Cyan $singleIOCname[0]
            Write-Host -NoNewline " Hash the bad hash: "
            Write-Host -ForegroundColor Yellow $singleIOC.value
        }
        $global:badHashes[$singleIOCname[0]] += "$($singleIOC.value),"
        if($Global:DebugMode){
            Write-host -NoNewline "Dragos Serial: "
            Write-Host -NoNewline -ForegroundColor Cyan $singleIOCname[1]
            Write-Host -NoNewline " Hash the bad hash: "
            Write-Host -ForegroundColor Yellow $singleIOC.value
        }
        $global:badHashes[$singleIOCname[1]] += "$($singleIOC.value),"
        if($Global:DebugMode){
            Write-host -NoNewline "Dragos Serial: "
            Write-Host -NoNewline -ForegroundColor Cyan $singleIOCname[2]
            Write-Host -NoNewline " Hash the bad hash: "
            Write-Host -ForegroundColor Yellow $singleIOC.value
        }
        $global:badHashes[$singleIOCname[2]] += "$($singleIOC.value),"
        if($Global:DebugMode){
            Write-host -NoNewline "Dragos Serial: "
            Write-Host -NoNewline -ForegroundColor Cyan $singleIOCname[3]
            Write-Host -NoNewline " Hash the bad hash: "
            Write-Host -ForegroundColor Yellow $singleIOC.value
        }
        $global:badHashes[$singleIOCname[3]] += "$($singleIOC.value),"
    }
    elseif($singleIOCname.length -eq 0){
        $singleIOCname = "JP_LS-$($singleIOC.last_seen.Substring(0,10))"
        if($Global:DebugMode){
            Write-host -NoNewline "Dragos Serial: "
            Write-Host -NoNewline -ForegroundColor Cyan $singleIOCname
            Write-Host -NoNewline " Hash the bad hash: "
            Write-Host -ForegroundColor Yellow $singleIOC.value
        }
        $global:badHashes[$singleIOCname] += "$($singleIOC.value),"
    }
    else{
        pause
    }

}
Write-Host -NoNewline "There were "
Write-Host -NoNewline -ForegroundColor Yellow $global:badHashes.count
Write-Host -NoNewline " DRAGOS product retreived with " 
Write-Host -NoNewline -ForegroundColor Cyan $finalMD5Count
Write-Host " SHA256 hashes downloaded."



#Build array of just Product Serials
$allProductKeys = @()
foreach($singleProfuctKeyThing in $global:badHashes.Keys){
    $allProductKeys += $singleProfuctKeyThing
}

#use array to call hash values, Trim trailing comma for each
foreach($productKey in $allProductKeys){
    $parseThisHash = $global:badHashes[$productKey]
    $parseThisHash = $parseThisHash.TrimEnd(',')
    $global:badHashes[$productKey] = $parseThisHash
}

#use Prodcut array to downlaod Description for each
$productMetadataCount = 0
foreach($productKey in $allProductKeys){
    if(!($productKey.StartsWith("JP_LS-") )){
        Start-Sleep -m 300
        $productMetadata = MetadatabyProductSerial $productKey
        $prodcutDescripClean = $productMetadata.executive_summary -replace('<[^>]+>','')
        $prodcutDescripClean = $prodcutDescripClean -replace("&nbsp;","")
        $global:productDescrips[$productKey] += $prodcutDescripClean
        $global:productTitles[$productKey] += $productMetadata.title
        $Global:productTLP[$productKey] += $productMetadata.tlp_level
    }
    $productMetadataCount++
    Write-Progress -Activity "Reading Metadata for DRAGOS Products" -CurrentOperation " $productKey "  -PercentComplete (($productMetadataCount * 100) / $($allProductKeys.Count)) -Status "Checked $productMetadataCount of $($allProductKeys.Count)" -Id 0
}
    Write-Progress -Activity "Reading Metadata for DRAGOS Products" -CurrentOperation " $productKey " -Completed -Status "Done!!" -Id 0

Write-Host -NoNewline "The Final count of unique Products is "
Write-Host -NoNewline -ForegroundColor Yellow $allProductKeys.count
Write-Host -NoNewline ". MetaData was downloaded for " 
Write-Host -NoNewline -ForegroundColor Cyan $global:productTitles.Count
Write-Host " Products!!"

$destinyChooser = "t"
$productUploadCount = 0
$intelIdsDragos = @()
While($destinyChooser -notlike "n"){
    $destinyChooser = Read-Host -Prompt "`nBegin uploading to Tanium? (y/n): "

    if($destinyChooser -like "y"){
        $productUploadCount = 0
        foreach($productKey in $allProductKeys){
            Write-Host ""
            #Build final name
            $finalIntelName = "ES | DWV-$($Global:productTLP[$productKey]) | $productKey-Hashes | $($global:productTitles[$productKey]) "    
            $quickAddHashtable = BuildJsonQuickAdd "$finalIntelName" "$($global:badHashes[$productKey])" "file_hash"
            #submit final object to quickadd parser
            $serverQuickAddObj = SubmitNewQuickAdd $quickAddHashtable


            pause
            #replace stock description with DRAGOS one
            if($global:productDescrips[$productKey]){
                $customQuickAddObj = $serverQuickAddObj -Replace("Known malicious file names.","$($global:productDescrips[$productKey])")
                }
            else{
                $customQuickAddObj = $serverQuickAddObj -Replace("Known malicious file names.","DRAGOS curated, known malicious Hashes names. Only MD5 and SHA256")
            }

            #send server response as XML to intels
            $finalIntelObj = SubmitIntelXML $customQuickAddObj
            $productUploadCount++
            [int]$productIntelId = $finalIntelObj.id
            $intelIdsDragos += $productIntelId
            Write-Progress -Activity "Uploading Hash IOCs to Tanium Intel" -CurrentOperation "Last uploaded intel: $finalIntelName"  -PercentComplete (($productUploadCount * 100) / $($allProductKeys.Count)) -Status "Uploaded: $productUploadCount. Remaining: $($($allProductKeys.Count) - $productUploadCount)" -Id 0
        }
        Write-Progress -Activity "Uploading Hash IOCs to Tanium Intel" -CurrentOperation "Completed! " -Completed -Status "Finished!!" -Id 0
        if($allProductKeys.Count -eq $intelIdsDragos.Count){
            Write-host "`nAll $($allProductKeys.count) items uploaded!"
            $destinyChooser = "n"
        }
        else{
            Write-Host "Seem something went wrong while uploading...."
            pause
            $destinyChooser = "n"
        }
    }
}


#Below Quickscans require configuration. YOU MUST POINT TO THE intelIDQuickScanAuto.ps1 file
$userQuickscanChoice = "t"
While($userQuickscanChoice -notlike "n"){
    $userQuickscanChoice = Read-Host "`nWould you like to begin Quick Scanning the last uploaded set of rules?(y/n)"
    if($userQuickscanChoice -like "y"){
        foreach($intelIdSingle in $intelIdsDragos){
                #location of intelIDQuickScanAuto.ps1 goes below
                & '.\intelQuickScanAuto.ps1' -intelIdArray $intelIdSingle
        }
    }
}




