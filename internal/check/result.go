package check

// NewResult creates the standard shell result for a check/hostname pair.
func NewResult(name, hostname string) Result {
	return Result{Check: name, Hostname: hostname}
}

// Finalize stores findings on res and derives the aggregate status.
func Finalize(res Result, findings []Finding) Result {
	res.Findings = findings
	res.Status = Aggregate(findings)
	return res
}

// Skip returns a skipped result with the provided message.
func Skip(name, hostname, msg string) Result {
	return Result{
		Check:    name,
		Hostname: hostname,
		Status:   StatusSkip,
		Findings: []Finding{{Status: StatusSkip, Message: msg}},
	}
}
