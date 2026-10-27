import unittest
from az_ready.coverage import gate_coverage

prefix='/subscriptions/demo/resourceGroups/rg-demo/providers/Microsoft.Storage/storageAccounts'
change={'status':'Succeeded','properties':{'changes':[{'changeType':'Modify','resourceId':prefix+'/vault01', 'delta':[{'path':'tags'}]}]}}
contract={'schemaVersion':1,'targets':[{'name':'blob-check','host':'store.blob.core.windows.net','expectedIPs':['10.0.4.5']}]}
monitor={'schemaVersion':1,'expectedTests':[{'source':'spoke1','destination':'blob','configuration':'tcp443'}]}
mapping={'schemaVersion':1,'resourceCoverage':[{'resourceIdPrefix':prefix,'requiredProbes':['blob-check'],
                                               'requiredMonitors':[{'source':'spoke1','destination':'blob','configuration':'tcp443'}]}]}

class CoverageTest(unittest.TestCase):
    def test_declared_not_proven(self):
        self.assertEqual(gate_coverage(change,contract,monitor,mapping)['decision'],'DECLARED_NOT_PROVEN')

    def test_unmapped_changes_fail(self):
        self.assertEqual(gate_coverage(change,contract,monitor,{'schemaVersion':1,'resourceCoverage':[]})['decision'],'FAIL')

    def test_missing_probe_fail(self):
        c={'schemaVersion':1,'targets':[{'name':'unrelated','host':'hello.internal','expectedIPs':['10.0.4.5']}]}
        self.assertEqual(gate_coverage(change,c,monitor,mapping)['decision'],'FAIL')

    def test_missing_monitor_fail(self):
        self.assertEqual(gate_coverage(change,contract,{'expectedTests':[]},mapping)['decision'],'FAIL')

    def test_no_changes_not_proven(self):
        c={'properties':{'changes':[{'changeType':'NoChange','resourceId':prefix+'/vault01'}]}}
        self.assertEqual(gate_coverage(c,contract,monitor,mapping)['decision'],'FAIL')

    def test_mapping_cannot_be_empty(self):
        m={'schemaVersion':1,'resourceCoverage':[{'resourceIdPrefix':prefix,'requiredProbes':[], 'requiredMonitors':[]}]}
        with self.assertRaises(ValueError):
            gate_coverage(change,contract,monitor,m)

    def test_short_prefix_rejected(self):
        m={'schemaVersion':1,'resourceCoverage':[{'resourceIdPrefix':'/subscriptions/','requiredProbes':['blob-check'],
            'requiredMonitors':monitor['expectedTests']}]}
        with self.assertRaises(ValueError):
            gate_coverage(change,contract,monitor,m)

if __name__=='__main__': unittest.main()
