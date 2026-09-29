package commands

import "strings"

// defenderExclusionsReport dumps the Defender policy that decides
// whether we live or die on a box: scan exclusions (path/process),
// Controlled Folder Access allowed apps + mode, Tamper Protection and
// real-time state. One view, so the operator stops correlating
// Get-MpPreference with Get-MpComputerStatus by hand. Read-only:
// never changes policy (the watcher heals it, the installer seeds it).
func defenderExclusionsReport() (string, error) {
	script := strings.Join([]string{
		`$p = Get-MpPreference`,
		`'--- ExclusionPath ---'`,
		`$p.ExclusionPath`,
		`'--- ExclusionProcess ---'`,
		`$p.ExclusionProcess`,
		`'--- ControlledFolderAccessAllowedApplications ---'`,
		`$p.ControlledFolderAccessAllowedApplications`,
		`'--- AttackSurfaceReductionOnlyExclusions ---'`,
		`$p.AttackSurfaceReductionOnlyExclusions`,
		`'EnableControlledFolderAccess: ' + $p.EnableControlledFolderAccess`,
		`$s = Get-MpComputerStatus`,
		`'IsTamperProtected: ' + $s.IsTamperProtected`,
		`'RealTimeProtectionEnabled: ' + $s.RealTimeProtectionEnabled`,
	}, "\n")
	return execPS(script)
}
