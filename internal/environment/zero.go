package environment

func Zero(values map[string]string) {
	// Go strings are immutable and may have runtime copies. Deleting references is best effort only.
	for key := range values {
		values[key] = ""
		delete(values, key)
	}
}
