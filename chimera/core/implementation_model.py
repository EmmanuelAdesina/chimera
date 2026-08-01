# chimera/core/implementation_model.py

import ast
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass

@dataclass
class ActualBehavior:
    behavior: str  # "Constructs SQL via f-string"
    location: str  # file:line
    data_flow: List[str]  # variable names involved
    sinks: List[str]  # SQL execution, shell exec, etc.

class ImplementationModelBuilder:
    """
    The diagram's 'Implementation Model' — recover what was ACTUALLY built.
    """
    
    def __init__(self):
        self.behaviors: List[ActualBehavior] = []
    
    def analyze_python_file(self, file_path: str, source: str) -> List[ActualBehavior]:
        tree = ast.parse(source)
        behaviors = []
        
        for node in ast.walk(tree):
            # Detect f-string SQL construction
            if isinstance(node, ast.JoinedStr):
                # Check if parent is assignment to 'query' or similar
                parent = self._get_parent(tree, node)
                if parent and isinstance(parent, ast.Assign):
                    for target in parent.targets:
                        if isinstance(target, ast.Name) and "query" in target.id.lower():
                            behaviors.append(ActualBehavior(
                                behavior="f-string SQL construction",
                                location=f"{file_path}:{node.lineno}",
                                data_flow=self._extract_variables(node),
                                sinks=["sql_execution"]
                            ))
            
            # Detect direct user input usage
            if isinstance(node, ast.Subscript):
                if isinstance(node.value, ast.Attribute):
                    if "request" in node.value.value.id.lower() if hasattr(node.value.value, 'id') else False:
                        behaviors.append(ActualBehavior(
                            behavior="Direct user input access",
                            location=f"{file_path}:{node.lineno}",
                            data_flow=[ast.unparse(node)],
                            sinks=["application_logic"]
                        ))
            
            # Detect os.system / subprocess calls
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in ["system", "popen", "call"]:
                        behaviors.append(ActualBehavior(
                            behavior="Shell execution",
                            location=f"{file_path}:{node.lineno}",
                            data_flow=self._extract_arguments(node),
                            sinks=["os_shell"]
                        ))
        
        self.behaviors.extend(behaviors)
        return behaviors
    
    def _get_parent(self, tree: ast.AST, node: ast.AST) -> Optional[ast.AST]:
        """Find parent node. Simplified — use ast.NodeVisitor for production."""
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                if child is node:
                    return parent
        return None
    
    def _extract_variables(self, node: ast.AST) -> List[str]:
        """Extract variable names from an AST node."""
        names = []
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                names.append(child.id)
        return list(set(names))
    
    def _extract_arguments(self, node: ast.Call) -> List[str]:
        """Extract argument strings from a call."""
        args = []
        for arg in node.args:
            try:
                args.append(ast.unparse(arg))
            except:
                args.append("<complex>")
        return args
    
    def get_all_behaviors(self) -> List[ActualBehavior]:
        return self.behaviors
    
    def get_behaviors_at_sink(self, sink_type: str) -> List[ActualBehavior]:
        return [b for b in self.behaviors if sink_type in b.sinks]