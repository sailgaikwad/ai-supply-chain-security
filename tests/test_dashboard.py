import ast

def test_dashboard_sandbox_integration():
    with open("app/dashboard/main.py", "r", encoding="utf-8") as f:
        tree = ast.parse(f.read())
        
    # Find all if statements
    if_statements = [n for n in ast.walk(tree) if isinstance(n, ast.If)]
    
    # Check if there is an if score < 40 or if score >= 40
    threshold_found = False
    for node in if_statements:
        if isinstance(node.test, ast.Compare):
            if isinstance(node.test.left, ast.Name) and node.test.left.id == 'score':
                if isinstance(node.test.comparators[0], ast.Constant) and node.test.comparators[0].value == 40:
                    threshold_found = True
                    break
    
    assert threshold_found, "Could not find a threshold check for score and 40 in main.py"
    
    # Check if dispatch_artifact is called
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)]
    dispatch_called = False
    for node in calls:
        if isinstance(node.func, ast.Name) and node.func.id == 'dispatch_artifact':
            dispatch_called = True
            break
            
    assert dispatch_called, "dispatch_artifact is not called in main.py"



