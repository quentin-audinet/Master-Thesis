from enum import Enum

"""
Language to describe the graph of conditions

Syntax : 

<NODE_TYPE=PRIMARY|SECONDARY|TRIGGER> <NODE_ID> SATISFIES <CONDITION> DEPENDS <LIST OF NODE_ID SEPARATED BY COMMA>
"""

# Errors

class NodeDefinitionError(Exception):
    pass

class NodeTypeError(NodeDefinitionError):
    pass
class NodeIDError(NodeDefinitionError):
    pass
class NodeConditionError(NodeDefinitionError):
    pass
class NodeUnrecognisedCondition(NodeConditionError):
    pass
class InvalidCountNumber(NodeConditionError):
    pass
class InvalidOperator(NodeConditionError):
    pass

class GraphCorrectnessError(Exception):
    pass
class GraphLoopError(GraphCorrectnessError):
    pass
class GraphNodeUnreachableError(GraphCorrectnessError):
    pass

# Types of node
class NodeType(Enum):
    PRIMARY = "PRIMARY"
    SECONDARY = "SECONDARY"
    TRIGGER = "TRIGGER"

# Representing a node
class Node:
    node_id: int
    kfunction: str
    node_type: NodeType
    condition: str
    children: [int]
    parents: [int]

    def __str__(self):
        return f"""Node ID: {self.node_id}
Type: {self.node_type}
Hook: {self.kfunction}
Condition:\n{self.condition}
Children: {self.children}
Parents: {self.parents}\n"""

    def __init__(self, definition: str):
        self.condition = ""
        self.parents = []
        self.children = []
        split_def = definition.split(" ")

        cursor = 0

        # Parse the type
        if split_def[cursor] == "PRIMARY":
            self.node_type = NodeType.PRIMARY
        elif split_def[cursor] == "SECONDARY":
            self.node_type = NodeType.SECONDARY
        elif split_def[cursor] == "TRIGGER":
            self.node_type = NodeType.TRIGGER
        else:
            raise NodeTypeError
        
        # Parse the ID
        cursor += 1
        try:
            node_id = int(split_def[cursor])
            if node_id < 0:
                raise NodeIDError
            self.node_id = node_id
        except:
            raise NodeIDError
        
        cursor += 1
        assert(split_def[cursor] == "SATISFIES")

        # Parse the condition
        cursor += 1
        condition_start = cursor
        try:
            while split_def[cursor] != "DEPENDS":
                cursor += 1
        except IndexError:
            raise NodeConditionError
        condition = split_def[condition_start:cursor]

        self.parse_condition(condition)

        assert(split_def[cursor] == "DEPENDS")
        
        # Parse the parents
        cursor += 1
        parents_list = "".join(split_def[cursor:]).strip()
        assert(parents_list[0] == "[" and parents_list[-1] == "]")
        # Verify the list isn't empty
        if parents_list[1:-1].strip() != "":
            for x in parents_list[1:-1].strip().split(','):
                self.parents.append(int(x.strip()))

    def parse_condition(self, condition: [str]):
        # The condition has the format : <KFUNCTION> [CALLED | PID | CONTEXT] <VALUE>
        # For CALLED, VALUE is : <OPERATOR> <INT VALUE> [AND / OR] ...
        # For PID, VALUE is a succession of conditions, including PID range
        # For CONTEXT, VALUE is : ARG_N->field1.field2 ... fieldn <OPERATOR> <TYPE> <VALUE> [AND/OR]
        cursor = 1
        self.kfunction = condition[0]
        rust_precondition = ""
        rust_condition = "Ok("
        # Parse according to the type of the condition
        # Add conditions until the end of the total condition
        while cursor < len(condition):
            if condition[cursor] == "CALLED" or condition[cursor] == "PID":
                if condition[cursor] == "CALLED":
                    variable = "count"
                else:
                    variable = "pid"
                cursor += 1

                rust_condition += variable
                if condition[cursor] in ['==', '!=', '>', '>=', '<', '<=']:
                    rust_condition+=condition[cursor]
                    cursor+=1
                    if condition[cursor].strip().isdigit():
                        rust_condition+=condition[cursor]
                        cursor += 1
                    else:
                        raise InvalidCountNumber
                else:
                    raise InvalidOperator

            # Trickiest condition
            elif condition[cursor] == "ARGS":
                # A private function to find the next field, if it exists and its position
                def next_separator(path: str):
                    next_arrow = path.find("->")
                    next_dot = path.find(".")
                    if next_arrow == -1 and next_dot == -1:
                            return {"type":None, "pos":len(path)}
                    elif next_dot == -1 or (next_arrow != -1 and next_arrow < next_dot):
                            return {"type":"->", "pos":next_arrow}
                    else:
                            return {"type":".", "pos":next_dot}
                cursor += 1

                arg_path = condition[cursor]
                # Get the arg number
                assert(arg_path.startswith("ARG_"))

                separator = next_separator(arg_path)
                pos = separator["pos"]
                arg_num = int(arg_path[4:pos])
                rust_precondition += f"let arg: usize = ctx.arg({arg_num}).ok_or(false)?;"

                # Parse the fields and read memory when a pointer is given
                while separator["type"] != None:
                    pos += len(separator["type"])
                    separator_type = separator["type"]
                    separator = next_separator(arg_path[pos:])
                    field = arg_path[pos:pos+separator["pos"]]

                    # The data is a pointer, read the memory
                    if separator_type == "->":
                        rust_precondition += "\nlet arg = unsafe { bpf_probe_read_kernel(arg as *const usize).map_err(|_| false)? };"

                    # The data is a field in the struct, access it
                    else:
                        rust_precondition += f"\nlet arg = arg.{field};"
                    
                    pos += separator["pos"]
                cursor += 1
                rust_precondition += f"\nlet arg{arg_num} = arg;\n"
                
                # Add the condition relative to the argument
                rust_condition += f"arg{arg_num}"
                if condition[cursor] in ['==', '!=', '>', '>=', '<', '<=']:
                    rust_condition+=condition[cursor]
                    cursor+=1
                    value = condition[cursor]
                    cursor+=1
                    assert("(" in value)
                    # This ensure we keep the value in parenthesis
                    # A single ' in a string is a problem for now
                    while value.count("(") > value.count(")") or value.count("'")%2 != 0 or value.count('"')%2 != 0:
                        value += " "+condition[cursor]
                        cursor+=1
                    value_type = value[:value.find("(")]
                    value = value[value.find("(")+1:value.rfind(")")]
                    rust_condition += value
                else:
                    raise InvalidOperator
            else:
                raise NodeUnrecognisedCondition
            # At this point, more data means a new condition
            if cursor < len(condition):
                if condition[cursor] == "AND":
                    rust_condition += " && "
                elif condition[cursor] == "OR":
                    rust_condition += " || "
                else:
                    raise InvalidOperator
                cursor += 1
        rust_condition = rust_precondition + "\n" + rust_condition + ")"
                                
        self.condition = rust_condition

        
        
# The graph containing the nodes
class Graph:
    size: int
    nodes: [Node]
    ids: [int]

    def __init__(self):
        self.size = 0
        self.nodes = []
        self.ids = {}
    
    # Add a new node to the graph
    def add(self, node: Node):
        if node.node_id in self.ids.keys():
            raise NodeIDError
        self.nodes.append(node)
        self.ids[node.node_id] = self.size   # Keep tracks of the node given their id
        self.size += 1

    def check_graph(self):
        # Check for the correctness of the graph
        # 1. Complete the relation parents <-> children
        # 2. No parents if and only if the node type is PRIMARY
        # 3. No children if and only if the node type is TRIGGER 
        # 4. No loop in the graph

        # 1.
        for node in self.nodes:
            for n in node.parents:
                self.nodes[self.ids[n]].children.append(node.node_id)
        for node in self.nodes:
            # 2.
            if (node.node_type == NodeType.PRIMARY and len(node.parents) != 0) or (len(node.parents) == 0 and node.node_type != NodeType.PRIMARY):
                raise GraphCorrectnessError
            # 3.
            elif (node.node_type == NodeType.TRIGGER and len(node.children) != 0) or (len(node.children) == 0 and node.node_type != NodeType.TRIGGER):
                raise GraphCorrectnessError
            # 4. For each primary node, get the full tree and assert each node is seen once
            if node.node_type == NodeType.PRIMARY:
                seen = [node.node_id]   # Track the node already seen
                to_see = node.children.copy() # The node remaining to see
                present = [node.node_id]
                while len(to_see) > 0:
                    current = to_see.pop(0)
                    if not current in present:
                        present.append(current)
                    if current in seen:
                        raise GraphLoopError
                    # See the node only if all its parents have already be seen
                    add = True
                    for parent in self.nodes[self.ids[current]].parents:
                        if parent not in seen:
                            add = False
                            break
                    if add:
                        seen.append(current)
                        to_see = [x for x in to_see if x != current]   # Remove future occurrences of the current node to see
                        to_see += self.nodes[self.ids[current]].children.copy()
                # If there is a loop, at all parents cannot be verified and some node won't be seen
                if sorted(present) != sorted(seen):
                    raise GraphLoopError
                
        pass
    
    def load_file(self, file_path: str):
        file = open(file_path, "r")
        for line in file.readlines():
            try:
                node = Node(line.strip())
                self.add(node)
            except:
                continue


def main():
    print("[+] Creating new graph")
    graph = Graph()
    print("[*] Loading graph.txt...")
    graph.load_file("graph.txt")
    print(f"[+] Graph loaded. ({graph.size} nodes)")
    print("[*] Checking for errors")
    graph.check_graph()
    print("[*] No error found !")
    for node in graph.nodes:
        print(node)
    return

if __name__ == "__main__":
    main()