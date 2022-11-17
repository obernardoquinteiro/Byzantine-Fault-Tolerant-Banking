IF %1.==. GOTO No1

set nByzantineServers=%1

setlocal ENABLEDELAYEDEXPANSION

set CMD="mvn exec:java -Dexec.args="!nByzantineServers!""
start cmd.exe /k !CMD!

goto End1

:No1
  @echo Insert Byzantine Servers
  goto End1

:End1
endlocal