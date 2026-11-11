from scanner.resource_checker import PATHS
def test_resource_scope_is_limited():assert len(PATHS)==4 and all(x.count('/')<=1 for x in PATHS)
