from datetime import datetime, timezone, timedelta
import unittest
from az_ready.monitor import gate_monitor

NOW = datetime(2026,10,27,14,30,tzinfo=timezone.utc)
SPEC = {'schemaVersion': 1, 'expectedTests': [{'source':'spoke-a-agent','destination':'payments-api','configuration':'tcp443'}],
        'maxAgeMinutes': 15, 'maxFailureRate': .05, 'minChecks': 10}

def sample(**changes):
    r = {'TimeGenerated': NOW.isoformat(), 'SourceName':'spoke-a-agent', 'DestinationName':'payments-api',
         'TestConfigurationName':'tcp443', 'TestResult':'Pass', 'ChecksTotal': 30, 'ChecksFailed': 0}
    r.update(changes)
    return r


class MonitorTests(unittest.TestCase):
    def gate(self, rows, spec=SPEC):
        return gate_monitor(rows, spec, now=NOW)

    def test_healthy(self):
        self.assertEqual(self.gate([sample()])['decision'], 'PASS')

    def test_missing_telemetry_not_green(self):
        self.assertEqual(self.gate([])['decision'], 'FAIL')

    def test_stale_telemetry_not_green(self):
        self.assertEqual(self.gate([sample(TimeGenerated=(NOW-timedelta(minutes=60)).isoformat())])['decision'], 'FAIL')

    def test_missing_required_test_fails(self):
        d = {**SPEC, 'expectedTests': [*SPEC['expectedTests'], {'source':'spoke-b-agent','destination':'db','configuration':'tcp1433'}]}
        self.assertEqual(self.gate([sample()], d)['decision'], 'FAIL')

    def test_indeterminate_fails(self):
        self.assertEqual(self.gate([sample(TestResult='Indeterminate')])['decision'], 'FAIL')

    def test_warning_fails(self):
        self.assertEqual(self.gate([sample(TestResult='Warning')])['decision'], 'FAIL')

    def test_failed_threshold(self):
        self.assertEqual(self.gate([sample(ChecksFailed=2)])['decision'], 'FAIL')

    def test_success_weighted(self):
        self.assertEqual(self.gate([sample(ChecksFailed=1,ChecksTotal=50), sample(ChecksFailed=0, ChecksTotal=50)])['decision'], 'PASS')

    def test_invalid_counts_fail(self):
        self.assertEqual(self.gate([sample(ChecksTotal=0)])['decision'], 'FAIL')

    def test_not_enough_checks_fail(self):
        self.assertEqual(self.gate([sample(ChecksTotal=3)])['decision'], 'FAIL')

    def test_rest_shape(self):
        row = sample()
        data={'tables':[{'name':'PrimaryResult', 'columns':[{'name': k, 'type':'string'} for k in row], 'rows':[list(row.values())]}]}
        self.assertEqual(self.gate(data)['decision'], 'PASS')

    def test_malformed_table_fail_closed(self):
        with self.assertRaises(ValueError):
            self.gate({'tables':[{'columns':[{'name':'x'}], 'rows':[[1,2]]}]})

    def test_invalid_datetime_fail_closed(self):
        with self.assertRaises(ValueError):
            self.gate([sample(TimeGenerated='yesterday')])

    def test_schema_rejects_duplicate_expected(self):
        d = {**SPEC,'expectedTests':[SPEC['expectedTests'][0],SPEC['expectedTests'][0]]}
        with self.assertRaises(ValueError):
            self.gate([],d)

    def test_multiple_group_and_unknown_rows(self):
        d = {**SPEC, 'expectedTests': [*SPEC['expectedTests'],{'source':'spoke-b-agent','destination':'db','configuration':'tcp1433'}]}
        extra = sample(SourceName='spoke-b-agent',DestinationName='db',TestConfigurationName='tcp1433')
        self.assertEqual(self.gate([sample(),extra,sample(SourceName='irrelevant')],d)['decision'], 'PASS')

if __name__ == '__main__':
    unittest.main()
