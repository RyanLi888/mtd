param(
    [string]$JavaHome = $env:JAVA_HOME,
    [switch]$SkipInstall
)

$ErrorActionPreference = 'Stop'
$DesktopRoot = Split-Path -Parent $PSScriptRoot
$RepoRoot = Split-Path -Parent $DesktopRoot
$Generated = Join-Path $DesktopRoot 'resources\generated'
$BackendOut = Join-Path $Generated 'backend'
$UiOut = Join-Path $Generated 'ui'
$RuntimeOut = Join-Path $Generated 'runtime'
$AgentOut = Join-Path $Generated 'agent'

Write-Host '[1/4] 构建本地后端'
Push-Location $RepoRoot
try {
    # 先安装全部模块，确保 Spring Boot 可执行包嵌入的是当前工作区模块，而不是本机缓存的旧版本。
    & mvn clean install -DskipTests
    if ($LASTEXITCODE -ne 0) { throw 'Maven 构建失败' }
} finally {
    Pop-Location
}

Write-Host '[2/4] 构建客户端界面'
Push-Location (Join-Path $RepoRoot 'mtd-ui')
try {
    $VueCli = Join-Path (Get-Location) 'node_modules\.bin\vue-cli-service.cmd'
    if (-not $SkipInstall -and -not (Test-Path $VueCli)) { & npm install }
    & npm run build:prod
    if ($LASTEXITCODE -ne 0) { throw '前端构建失败' }
} finally {
    Pop-Location
}

Write-Host '[3/4] 准备应用资源'
if (Test-Path $Generated) { Remove-Item -LiteralPath $Generated -Recurse -Force }
New-Item -ItemType Directory -Path $BackendOut, $UiOut, $AgentOut | Out-Null
Copy-Item -LiteralPath (Join-Path $RepoRoot 'mtd-admin\target\mtd-admin.jar') -Destination $BackendOut
Copy-Item -Path (Join-Path $RepoRoot 'mtd-ui\dist\*') -Destination $UiOut -Recurse
Copy-Item -Path (Join-Path $RepoRoot 'mtd-agent\*') -Destination $AgentOut -Recurse

Write-Host '[4/4] 生成精简 Java 运行时'
if (-not $JavaHome) { throw '未设置 JAVA_HOME，请传入 -JavaHome 指向 JDK 17' }
$Jlink = Join-Path $JavaHome 'bin\jlink.exe'
if (-not (Test-Path $Jlink)) { throw "找不到 jlink：$Jlink" }
& $Jlink --add-modules java.se,java.instrument,jdk.unsupported,jdk.crypto.ec --strip-debug --no-header-files --no-man-pages --compress=2 --output $RuntimeOut
if ($LASTEXITCODE -ne 0) { throw 'JRE 运行时生成失败' }

Write-Host "资源准备完成：$Generated"
Write-Host '下一步：在 mtd-desktop 中执行 npm run dist'
