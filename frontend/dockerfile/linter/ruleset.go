package linter

import (
	"fmt"
)

var (
	RuleStageNameCasing = LinterRule[func(string) string]{
		Name:        "StageNameCasing",
		Description: "Stage names should be lowercase",
		Format: func(stageName string) string {
			return fmt.Sprintf("Stage name '%s' should be lowercase", stageName)
		},
	}
	RuleFromAsCasing = LinterRule[func(string, string) string]{
		Name:        "FromAsCasing",
		Description: "The 'as' keyword should match the case of the 'from' keyword",
		Format: func(from, as string) string {
			return fmt.Sprintf("'%s' and '%s' keywords' casing do not match", as, from)
		},
	}
	RuleNoEmptyContinuations = LinterRule[func() string]{
		Name:        "NoEmptyContinuations",
		Description: "Empty continuation lines will become errors in a future release",
		URL:         "https://github.com/moby/moby/pull/33719",
		Format: func() string {
			return "Empty continuation line"
		},
	}
	RuleSelfConsistentCommandCasing = LinterRule[func(string) string]{
		Name:        "SelfConsistentCommandCasing",
		Description: "Commands should be in consistent casing (all lower or all upper)",
		Format: func(command string) string {
			return fmt.Sprintf("Command '%s' should be consistently cased", command)
		},
	}
	RuleFileConsistentCommandCasing = LinterRule[func(string, string) string]{
		Name:        "FileConsistentCommandCasing",
		Description: "All commands within the Dockerfile should use the same casing (either upper or lower)",
		Format: func(violatingCommand, correctCasing string) string {
			return fmt.Sprintf("Command '%s' should match the case of the command majority (%s)", violatingCommand, correctCasing)
		},
	}
	RuleDuplicateStageName = LinterRule[func(string) string]{
		Name:        "DuplicateStageName",
		Description: "Stage names should be unique",
		Format: func(stageName string) string {
			return fmt.Sprintf("Duplicate stage name %q, stage names should be unique", stageName)
		},
	}
	RuleReservedStageName = LinterRule[func(string) string]{
		Name:        "ReservedStageName",
		Description: "Reserved stage names should not be used to name a stage",
		Format: func(reservedStageName string) string {
			return fmt.Sprintf("Stage name should not use the same name as reserved stage %q", reservedStageName)
		},
	}
	RuleMaintainerDeprecated = LinterRule[func() string]{
		Name:        "MaintainerDeprecated",
		Description: "The maintainer instruction is deprecated, use a label instead to define an image author",
		URL:         "https://docs.docker.com/reference/dockerfile/#maintainer-deprecated",
		Format: func() string {
			return "Maintainer instruction is deprecated in favor of using label"
		},
	}
	RuleUndeclaredArgInFrom = LinterRule[func(string) string]{
		Name:        "UndeclaredArgInFrom",
		Description: "FROM command must use declared ARGs",
		Format: func(baseArg string) string {
			return fmt.Sprintf("FROM argument '%s' is not declared", baseArg)
		},
	}
)
