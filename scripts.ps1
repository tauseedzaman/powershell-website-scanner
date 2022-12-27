$website = Read-Host "Enter The website url Seperated By Spaces "
$websites = $website.Split(' ');

$cyren_header = @{
    "Authorization" = "Bearer api-key or token"
    "Content-Type"  = "application/json"
}

$virus_total_body = @{
    'apikey'   = 'api-key'  
    'resource' = $website
}

foreach ($website in $websites) {
    Write-Host "`n==================================================================================="
    Write-Host Checking $website
    Write-Host "===================================================================================`n"


    # ================================== categorize website ==============================================
    $cyren__body = [PSCustomObject]@{
        'url' = "$website"
    }
    $cyren__body = ConvertTo-Json -InputObject $cyren__body
    $cyren__res = Invoke-WebRequest -Uri "https://api-url.cyren.com/api/v1/free/url" -Method Post -Headers $cyren_header -Body $cyren__body
    
    $cyren__data = ConvertFrom-Json $cyren__res
    # Write-Host "============================== Checking category of $website =============================="
    Write-Host Category of $website :  $cyren__data.categoryNames
    
    
    
    # ============================= Viruse total =============================================================
    $uri = 'https://www.virustotal.com/vtapi/v2/url/report'
    $virus_total = Invoke-WebRequest -Uri $uri -Method POST  -Body $virus_total_body

    $data = ConvertFrom-Json $virus_total
    $scans = $data.scans

    Write-Host "Virus Total Scane Results"
    Write-Host "====================================="
    Write-Host BlockList: `t`t           $scans.BlockList.result
    Write-Host CyberCrime: `t`t          $scans.CyberCrime.result
    Write-Host MalwarePatrol: `t`t       $scans.MalwarePatrol.result
    Write-Host OpenPhish: `t`t           $scans.OpenPhish.result
    Write-Host ThreatHive: `t`t          $scans.ThreatHive.result
    Write-Host Malwared: `t`t            $scans.Malwared.result
    Write-Host Phishing Database: `t   $scans.'Phishing Database'.result
    Write-Host Web Security Guard: `t  $scans.'Web Security Guard'.result
    Write-Host CyRadar: `t`t             $scans.CyRadar.result
    Write-Host AlienVault: `t`t          $scans.AlienVault.result
    Write-Host

    if ($data.positives -gt 0) {
        Write-Host $data.positives "Security vendor flagged this domain as malicious"
    }
    else {
        Write-Host "No security vendors flagged this domain as malicious"
    }
    Write-Host Community Score  $data.positives '/' $data.total
    Write-Host

    # ============================= urlvoid result  =============================================================
    Write-Host "urlvoid Scane Results"
    Write-Host "====================================="
    $res = Invoke-WebRequest "https://www.urlvoid.com/scan/$website/"
    $products = $res.ParsedHtml.getElementsByClassName('table table-custom table-striped')
    Write-Output $products[0].outerText.Split("`n") | Foreach-Object { 
        if ($_ -match "Detections*") { 
            Write-Host Detections Counts:`t`t         $_.Replace("Detections Counts", "") 
        }
        elseif ($_ -match "Domain Registration*") {
            Write-Host Domain Registration:`t`t         $_.Replace("Domain Registration", "") 
        }
        elseif ($_ -match "Latitude\\Longitude*") {
            Write-Host Latitude\Longitude:`t`t         $_.Replace("Latitude\Longitude", "") 
        }
        elseif ($_ -match "Region*") {
            Write-Host Region:`t`t`t         $_.Replace("Region", "")
        }
        elseif ($_ -match "IP Address*") {
            Write-Host IP:`t`t`t ($_.Replace("IP Address", "")).Replace("Find Websites  |  IPVoid  |  Whois", "") 
        }
    }
    
    # more details from urlvoid
    Write-Output $products[1].outerText.Split("`n") | Foreach-Object { 
        if ($_ -match "CRDF*") { 
            Write-Host CRDF:`t`t`t ($_.Replace("CRDF", "")).Replace("View More Details", "") 
        }
        elseif ($_ -match "Artists Against 419*") {
            Write-Host Against 419:`t`t  ($_.Replace("Artists Against 419", "")).Replace("View More Details", "") 
        }
        elseif ($_ -match "AZORult Tracker*") {
            Write-Host AZORult:`t`t  ($_.Replace("AZORult Tracker", "")).Replace("View More Details", "") 
        }
        elseif ($_ -match "BitDefender*") {
            Write-Host BitDefender:`t`t  ($_.Replace("BitDefender", "")).Replace("View More Details", "") 
        }
        elseif ($_ -match "CyberCrime*") {
            Write-Host CyberCrime:`t`t  ($_.Replace("CyberCrime", "")).Replace("View More Details", "") 
        }
        elseif ($_ -match "Spam404*") {
            Write-Host Spam404:`t`t  ($_.Replace("Spam404", "")).Replace("View More Details", "") 
        }
    }
    Write-Host `n
}
