// Package kovaskill embeds the kova-verify skill so the CLI can refresh installed copies of it
// (`kova skills refresh`, run by `kova upgrade`): a stale skill tells the model the opposite of
// what the current binary does.
package kovaskill

import _ "embed"

// SkillMD is the current skills/kova-verify/SKILL.md.
//
//go:embed SKILL.md
var SkillMD string

// Name is the skill's frontmatter name, used to find installed copies.
const Name = "kova-verify"
