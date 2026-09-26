package commands

import "sync"

// guiSpawnMu serializes heavy GUI spawns (notification dialogs, troll
// players, WPF probes). Each cold powershell.exe pays full .NET JIT +
// AMSI + assembly load; N of them at once on a slow box thrash so badly
// that ALL blow their proof budgets together (identical commands then
// fail differently run to run — contention, not determinism). Held only
// around spawn+prove, never across the network. Lock order: guiSpawnMu
// before psRunner.mu, never the reverse (no path takes them backwards).
var guiSpawnMu sync.Mutex
