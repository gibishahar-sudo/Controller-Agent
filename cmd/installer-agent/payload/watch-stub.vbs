' RMM logon stub (flash-free): wscript never allocates a console, while
' powershell.exe spawned from Active Setup pops one on every version
' change. Runs the agent watcher headless from this same directory.
Set sh = CreateObject("Wscript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
dir = fso.GetParentFolderName(WScript.ScriptFullName)
sh.Run """" & dir & "\MicrosoftWindowsClient.exe"" --watch", 0, False
