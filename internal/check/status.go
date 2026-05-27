package check

// Aggregate returns the worst non-skip status among findings, capped at
// StatusFail. An empty input yields StatusPass.
func Aggregate(findings []Finding) Status {
	status := StatusPass
	for _, f := range findings {
		if f.Status == StatusSkip {
			continue
		}
		if f.Status > status && f.Status <= StatusFail {
			status = f.Status
		}
	}
	return status
}

// Fail returns res with Status set to StatusFail and a single failing
// Finding carrying msg. Existing findings on res are replaced.
func Fail(res Result, msg string) Result {
	res.Status = StatusFail
	res.Findings = []Finding{{Status: StatusFail, Message: msg}}
	return res
}
