rule MONOLITH_TEST {
    meta:
        description = "Monolith EDR integration test pattern"
        author = "Monolith EDR"
        severity = "critical"
    strings:
        $test = "MONOLITH-EDR-INTEGRATION-TEST-PATTERN-2026"
condition:
        $test
}
