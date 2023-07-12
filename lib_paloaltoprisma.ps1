# [CLASSES] -----------------------------------------------------------------

class prisma_tunnel_profile {
    [string]$name = [String]::Empty
<#    $authentication_override = @{
        accept_cookie = @{
            $cookie_encrypt_decrypt_cert = "Authentication Cookie Cert"
            $generate_cookie = $true
            cookie_lifetime = @{
                lifetime_in_days = 0
                lifetime_in_hours = 0
                lifetime_in_minutes = 0
            }
        }
    }
#>
    #$source_user = @("any")
    #$os = @("any")
    $split_tunneling = @{
        exclude_domains =  @{
            list = @(
                @{
                name = "andbank.com"
                ports = @(80, 443)
                }
            )
        }
    }

    prisma_tunnel_profile ([string]$name) {
        $this.name = $name
    }

    add_domainexclusion ([string]$name, [int[]]$ports) {
        if ($this.split_tunneling.exclude_domains.list.name -contains $name) {
            Write-Host "$name already in list, not added." -ForegroundColor Red
            return
        }
        $this.split_tunneling.exclude_domains.list += @{
            name = $name
            ports = $ports
        }
    }

    add_bulkdomainexclusion ([string[]]$domainlist, [int[]]$ports) {
        foreach ($domain in $domainlist) {
            $this.add_domainexclusion($domain.Trim(), $ports)
        }
    }

    [string] toJson() {
        return ($this | ConvertTo-Json -Depth 100)
    }
}

class prisma_urlcategory {
    [string]$description = [string]::Empty
    [string]$name = [string]::Empty
    [string]$type = "URL List"
    [string[]]$list = @()

    prisma_urlcategory ($name, [string[]]$list, $description = "") {
        $this.name = $name
        $this.description = $description
        $this.list = $list
    }

    [string] toJson() {
        return ($this | ConvertTo-Json -Depth 100)
    }
}

class prisma_address {
    [string]$description = [string]::Empty
    [string]$name = [string]::Empty
    $tag = @()
    [string]$ip_netmask = [string]::Empty

    prisma_address ([string]$name, [string[]]$ip_netmask, [string]$description = [string]::Empty, $tags = @()) {
        $this.name = $name
        $this.ip_netmask = $ip_netmask
        $this.description = $description
        
        foreach ($tag in $tags){ $this.tag += $tag }
    }

    [string] toJson() {
        return ($this | ConvertTo-Json -Depth 100)
    }
}

class prisma_address_group {
    [string]$description = [string]::Empty
    [string]$name = [string]::Empty
    $tag = @()
    $static = @()

    prisma_address_group ([string]$name, [string[]]$addresses, [string]$description = [string]::Empty, $tags = @()) {
        $this.name = $name
        $this.description = $description
        
        foreach ($address in $addresses){ $this.static += $address }
        foreach ($tag in $tags){ $this.tag += $tag }
    }

    [string] toJson() {
        return ($this | ConvertTo-Json -Depth 100)
    }
}

# [FUNCTIONS] ---------------------------------------------------------------

# Get public Prisma ip's
function Get-PrismaAccessIP ([String]$ApiKey, [String]$serviceType) {

    $headers = @{
        'header-api-key' = "${ApiKey}"
        'Content-Type' = "application/json"
    }

    $a = "" | Select-Object @{n="serviceType";e={$serviceType}}, @{n="location";e={"deployed"}}, @{n="addrType";e={"active"}}

    $r = Invoke-WebRequest "https://api.prod.datapath.prismaaccess.com/getPrismaAccessIP/v2" `
         -Method Post `
         -Headers $headers `
         -Body ($a | ConvertTo-Json)

    if ($r.StatusCode -eq 200) {
        $result = ($r.content | ConvertFrom-Json).result.foreach({
            $z=$_.zone
            $details = $_.address_details
            foreach ($detail in $details){
                "" | select @{n="Zone"; e={$z}}, @{n="serviceType"; e={$detail.serviceType}}, @{n="Address"; e={$detail.address}}
            }
        })
        return $result
    }
}

# Get Prisma access token for authorization bearer
function Get-PrismaAccessToken ([string]$username, [string]$password) {

    $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $username, $password)))

    $headers = @{
        Content='application/x-www-form-urlencoded'
        Authorization=("Basic {0}" -f $base64AuthInfo)
    }
    
    $result = Invoke-RestMethod https://auth.apps.paloaltonetworks.com/oauth2/access_token `
        -Headers $headers `
        -Method Post `
        -Body "grant_type=client_credentials&scope=tsg_id:1942485575"
    
    if ($result.access_token) {
        return $result.access_token
    }
}

# Get 'Address' objects
function Get-PrismaAddress ([String]$Token, [string]$Folder) {

    $headers = @{
        Authorization = "Bearer ${Token}"
        'Content-Type' = "application/json"
    }

    $r = Invoke-RestMethod "https://api.sase.paloaltonetworks.com/sse/config/v1/addresses?folder=${Folder}" -Method Get -Headers $headers

    return $r.data
}

# Get GlobalProtect tunnel profiles
function Get-PrismaTunnelProfiles ([String]$Token) {

    $headers = @{
        Authorization = "Bearer ${Token}"
        'Content-Type' = "application/json"
    }

    $r = Invoke-WebRequest "https://api.sase.paloaltonetworks.com/sse/config/v1/mobile-agent/tunnel-profiles?folder=Mobile Users" -Method Get -Headers $headers

    if ($r.StatusCode -eq 200) {
        return $r.content
    }
}

# Update GlobalProtect tunnel profiles
function Update-PrismaTunnelProfiles ([String]$Token) {

    $headers = @{
        Authorization = "Bearer ${Token}"
        'Content-Type' = "application/json"
    }

    $r = Invoke-WebRequest 'https://api.sase.paloaltonetworks.com/sse/config/v1/mobile-agent/tunnel-profiles?folder=Mobile Users' -Method Get -Headers $headers

    if ($r.StatusCode -eq 200) {
        return $r.content
    }
}

# Create new Prisma tunnel profile
function New-PrismaTunnelProfile ([String]$Token, [prisma_tunnel_profile]$tunnel_profile) {

    $headers = @{
        Authorization = "Bearer ${Token}"
        'Content-Type' = "application/json"
    }

    $body = $tunnel_profile.toJson()

    $body > \temp\body.txt
    $body = '{"name":"TEST"}'

    $r = Invoke-RestMethod 'https://api.sase.paloaltonetworks.com/sse/config/v1/mobile-agent/tunnel-profiles?folder=Mobile Users'`
        -Body $body `
        -Method Post `
        -Headers $headers

    if ($r.StatusCode -eq 200) {
        return $r.content
    }
}

# Update existing Prisma tunnel profile
function Update-PrismaTunnelProfile ([String]$Token, [prisma_tunnel_profile]$tunnel_profile) {

    $headers = @{
        Authorization = "Bearer ${Token}"
        'Content-Type' = "application/json"
    }

    $body = $tunnel_profile.toJson()

    $body > \temp\body.txt

    $r = Invoke-RestMethod 'https://api.sase.paloaltonetworks.com/sse/config/v1/mobile-agent/tunnel-profiles?folder=Mobile Users'`
        -Body $body `
        -Method Put `
        -Headers $headers

    if ($r.StatusCode -eq 200) {
        return $r.content
    }
}

# Create new Prisma URL category
function New-PrismaURLCategory ([String]$Token, [prisma_urlcategory]$category) {

    Write-Host "Creating URL Category $($category.Name)"

    $headers = @{
        Authorization = "Bearer ${Token}"
        'Content-Type' = "application/json"
    }

    $body = $category.toJson()

    $body > \temp\body.txt

    $r = Invoke-RestMethod 'https://api.sase.paloaltonetworks.com/sse/config/v1/url-categories?folder=Shared'`
        -Body $body `
        -Method Post `
        -Headers $headers

    if ($r.StatusCode -eq 200) {
        return $r.content
    }
}

# Create new Prisma 'Address' object
function New-PrismaAddress ([String]$Token, [prisma_address]$address, [string]$Folder) {

    Write-Host "Creating Prisma Address $($address.Name)"

    $headers = @{
        Authorization = "Bearer ${Token}"
        'Content-Type' = "application/json"
    }

    $body = $address.ToJson()

    $r = Invoke-RestMethod "https://api.sase.paloaltonetworks.com/sse/config/v1/addresses?folder=${Folder}"`
        -Body $body `
        -Method Post `
        -Headers $headers

    return $r.data
}

# Update Prisma 'Address' object
function Update-PrismaAddress ([String]$Token, [string]$Id, [prisma_address]$address) {

    Write-Host "Updating Prisma Address $($address.Name) (${Id})"

    $headers = @{
        Authorization = "Bearer ${Token}"
        'Content-Type' = "application/json"
    }

    $body = $address.ToJson()

    $r = Invoke-RestMethod "https://api.sase.paloaltonetworks.com/sse/config/v1/addresses/${Id}"`
        -Body $body `
        -Method Put `
        -Headers $headers

    return $r.data
}

# Get Prisma 'Address Group' objects
function Get-PrismaAddressGroup ([String]$Token, [string]$Folder) {

    Write-Host "Getting Prisma Address Groups from folder: ${Folder}"

    $headers = @{
        Authorization = "Bearer ${Token}"
        'Content-Type' = "application/json"
    }

    $r = Invoke-RestMethod "https://api.sase.paloaltonetworks.com/sse/config/v1/address-groups?folder=${Folder}"`
        -Method Get `
        -Headers $headers

    return $r.data
    
}

# Get Prisma 'Security Rule' objects
function Get-PrismaSecurityRules ([String]$Token, [string]$Folder) {

    Write-Host "Getting Prisma Security Rules from folder: ${Folder}"

    $headers = @{
        Authorization = "Bearer ${Token}"
        'Content-Type' = "application/json"
    }

    $r = Invoke-RestMethod "https://api.sase.paloaltonetworks.com/sse/config/v1/security-rules?folder=${Folder}"`
        -Method Get `
        -Headers $headers

    return $r.data
    
}

# Create new Prisma 'Address Group' object
function New-PrismaAddressGroup ([String]$Token, [prisma_address_group]$addressgroup, [string]$Folder) {

    Write-Host "Creating Prisma Address Group $($addressgroup.Name)"

    $headers = @{
        Authorization = "Bearer ${Token}"
        'Content-Type' = "application/json"
    }

    $body = $addressgroup.ToJson()

    $r = Invoke-RestMethod "https://api.sase.paloaltonetworks.com/sse/config/v1/address-groups?folder=${Folder}"`
        -Body $body `
        -Method Post `
        -Headers $headers

    return $r.data
}
